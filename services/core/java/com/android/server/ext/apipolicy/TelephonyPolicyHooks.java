/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.ext.apipolicy;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.telephony.CellIdentity;
import android.telephony.CellIdentityCdma;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityNr;
import android.telephony.CellIdentityTdscdma;
import android.telephony.CellIdentityWcdma;
import android.telephony.CellInfo;
import android.telephony.CellInfoCdma;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoNr;
import android.telephony.CellInfoTdscdma;
import android.telephony.CellInfoWcdma;
import android.telephony.ServiceState;
import android.util.ArrayMap;
import android.util.Slog;

import com.android.server.LocalServices;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Telephony hook points adapter bridging {@code TelephonyRegistry} and
 * {@link ApiPolicyInternal}.
 *
 * <p>The hooks cover the delivery egress inside {@code TelephonyRegistry}: the notify methods and
 * the {@code listen()}/{@code checkPossibleMissNotify} catch-up paths. The synchronous getters
 * served by the telephony process are filtered by
 * {@code com.android.phone.TelephonySyncPolicyHooks}, which evaluates the same point ids (drop
 * only).
 *
 * <p>Cell info is evaluated one entry at a time, every other point receives a single object. Only
 * replacement copies are ever built, so the cached {@code TelephonyRegistry} state is never
 * modified and a rewrite can not leak into another caller or into {@code dumpsys}.
 */
public final class TelephonyPolicyHooks {

    private static final String TAG = "TelephonyPolicyHooks";

    public static final String POINT_CELL_INFO = "telephony.cell_info";
    public static final String POINT_CELL_LOCATION = "telephony.cell_location";
    public static final String POINT_SERVICE_STATE = "telephony.service_state";

    private static volatile ApiPolicyInternal sCachedService;

    /**
     * System components (system_server, phone, bluetooth, shell, ...) are never subject to
     * script policy: filtering them would break telephony, connectivity and system UI.
     */
    private static boolean isExempt(@Nullable Caller caller) {
        return caller == null || caller.uid < android.os.Process.FIRST_APPLICATION_UID;
    }

    private TelephonyPolicyHooks() {}

    @Nullable
    private static ApiPolicyInternal getService() {
        ApiPolicyInternal svc = sCachedService;
        if (svc == null) {
            svc = LocalServices.getService(ApiPolicyInternal.class);
            if (svc != null) {
                sCachedService = svc;
            }
        }
        return svc;
    }

    /** Cheap fast path for callers that want to skip building a context. */
    public static boolean isPointActive(String pointId) {
        final ApiPolicyInternal svc = getService();
        return svc != null && svc.isPointActive(pointId);
    }

    static void registerHookPoints(ApiPolicyInternal service) {
        service.registerHookPoint(
                POINT_CELL_INFO,
                "telephony",
                "Per-caller cell info delivery in TelephonyRegistry.notifyCellInfoForSubscriber");
        service.registerHookPoint(
                POINT_CELL_LOCATION,
                "telephony",
                "Per-caller cell location delivery in"
                        + " TelephonyRegistry.notifyCellLocationForSubscriber");
        service.registerHookPoint(
                POINT_SERVICE_STATE,
                "telephony",
                "Per-caller service state cell identity in"
                        + " TelephonyRegistry.notifyServiceStateForPhoneId");
    }

    /** Caller identity captured from a {@code TelephonyRegistry.Record}. */
    public static final class Caller {
        public final int uid;
        public final int pid;
        @Nullable public final String packageName;
        @Nullable public final String featureId;
        @NonNull public final String permissionLevel;

        public Caller(int uid, int pid, @Nullable String packageName, @Nullable String featureId,
                @NonNull String permissionLevel) {
            this.uid = uid;
            this.pid = pid;
            this.packageName = packageName;
            this.featureId = featureId;
            this.permissionLevel = permissionLevel;
        }
    }

    /**
     * Filters or rewrites one cell info list for one registrant.
     *
     * <p>{@code drop} removes that entry; {@code modify} merges the returned fields and rebuilds
     * the identity. An entry that can not be rebuilt is delivered unchanged.
     */
    @Nullable
    public static List<CellInfo> onCellInfo(@Nullable Caller caller,
            @Nullable List<CellInfo> infos) {
        if (isExempt(caller) || infos == null || infos.isEmpty()) {
            return infos;
        }
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_CELL_INFO)) {
                return infos;
            }

            final int size = infos.size();
            final ArrayList<CellInfo> out = new ArrayList<>(size);
            boolean changed = false;
            for (int i = 0; i < size; i++) {
                final CellInfo info = infos.get(i);
                final Object[] ctx = buildContext(caller, size, i + 1, cellInfoToKv(info));
                final ArrayMap<String, Object> decision = svc.evaluate(POINT_CELL_INFO, ctx);
                if (decision == null) {
                    out.add(info);
                    continue;
                }
                final String action = getAction(decision);
                if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                    changed = true;
                    continue;
                }
                if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                    final CellInfo rewritten =
                            rewriteCellInfo(info, decision, svc, POINT_CELL_INFO);
                    if (rewritten == null) {
                        out.add(info);
                        continue;
                    }
                    out.add(rewritten);
                    changed = true;
                    continue;
                }
                out.add(info);
            }
            return changed ? out : infos;
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_CELL_INFO, t);
            return infos;
        }
    }

    /**
     * Filters or rewrites the cell identity delivered by {@code CellLocationListener}.
     *
     * @param droppedOut set to {@code true} when the script explicitly dropped the callback; a
     *     {@code null} return with {@code false} means "no identity yet" and must still be
     *     delivered
     */
    @Nullable
    public static CellIdentity onCellLocation(@Nullable Caller caller,
            @Nullable CellIdentity identity, @NonNull boolean[] droppedOut) {
        droppedOut[0] = false;
        if (isExempt(caller) || identity == null) {
            return identity;
        }
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_CELL_LOCATION)) {
                return identity;
            }
            final Object[] ctx = buildContext(caller, 1, 1, cellIdentityToKv(identity));
            final ArrayMap<String, Object> decision = svc.evaluate(POINT_CELL_LOCATION, ctx);
            if (decision == null) {
                return identity;
            }
            final String action = getAction(decision);
            if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                droppedOut[0] = true;
                return null;
            }
            if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                final CellIdentity rewritten = rewriteCellIdentity(
                        identity, decision, svc, POINT_CELL_LOCATION);
                return (rewritten != null) ? rewritten : identity;
            }
            return identity;
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_CELL_LOCATION, t);
            return identity;
        }
    }

    /**
     * Applies the cell identity policy to every network registration info of one service state
     * copy.
     *
     * <p>{@code drop} removes every identifying field of the cell identity while keeping the RAT
     * type (the caller still receives a valid state); {@code modify} merges the returned
     * fields.
     */
    @Nullable
    public static ServiceState onServiceState(@Nullable Caller caller,
            @Nullable ServiceState state) {
        if (isExempt(caller) || state == null) {
            return state;
        }
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_SERVICE_STATE)) {
                return state;
            }
            final ApiPolicyInternal service = svc;
            return state.createCellIdentityRewrittenCopy(identity -> {
                final Object[] ctx = buildContext(caller, 1, 1, cellIdentityToKv(identity));
                final ArrayMap<String, Object> decision =
                        service.evaluate(POINT_SERVICE_STATE, ctx);
                if (decision == null) {
                    return null;
                }
                final String action = getAction(decision);
                if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                    return stripToPlmn(identity);
                }
                if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                    return rewriteCellIdentity(identity, decision, service, POINT_SERVICE_STATE);
                }
                return null;
            });
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_SERVICE_STATE, t);
            return state;
        }
    }

    private static Object[] buildContext(Caller caller, int count, int index, Object[] item) {
        return new PolicyScriptEngine.KvBuilder(9)
                .put("uid", (long) caller.uid)
                .put("pid", (long) caller.pid)
                .put("user_id", (long) android.os.UserHandle.getUserId(caller.uid))
                .put("package_name", caller.packageName)
                .put("attribution_tag", caller.featureId)
                .put("permission_level", caller.permissionLevel)
                .put("count", (long) count)
                .put("batch_index", (long) index)
                .put("item", item)
                .build();
    }

    private static String getAction(ArrayMap<String, Object> decision) {
        final Object raw = decision.get("action");
        return (raw instanceof String s) ? s : ApiPolicyInternal.ACTION_ALLOW;
    }

    @Nullable
    private static CellInfo rewriteCellInfo(CellInfo info, ArrayMap<String, Object> decision,
            ApiPolicyInternal svc, String pointId) {
        final CellIdentity identity = info.getCellIdentity();
        if (identity == null) {
            return null;
        }
        final CellIdentity rewritten = rewriteCellIdentity(identity, decision, svc, pointId);
        if (rewritten == null) {
            return null;
        }
        if (info instanceof CellInfoLte lte) {
            final CellInfoLte copy = new CellInfoLte(lte);
            copy.setCellIdentity((CellIdentityLte) rewritten);
            return copy;
        }
        if (info instanceof CellInfoGsm gsm) {
            final CellInfoGsm copy = new CellInfoGsm(gsm);
            copy.setCellIdentity((CellIdentityGsm) rewritten);
            return copy;
        }
        if (info instanceof CellInfoWcdma wcdma) {
            final CellInfoWcdma copy = new CellInfoWcdma(wcdma);
            copy.setCellIdentity((CellIdentityWcdma) rewritten);
            return copy;
        }
        if (info instanceof CellInfoCdma cdma) {
            final CellInfoCdma copy = new CellInfoCdma(cdma);
            copy.setCellIdentity((CellIdentityCdma) rewritten);
            return copy;
        }
        if (info instanceof CellInfoNr nr) {
            return new CellInfoNr(nr.getCellConnectionStatus(), nr.isRegistered(),
                    nr.getTimeStamp(), (CellIdentityNr) rewritten,
                    (android.telephony.CellSignalStrengthNr) nr.getCellSignalStrength());
        }
        if (info instanceof CellInfoTdscdma tdscdma) {
            final CellInfoTdscdma copy = new CellInfoTdscdma(tdscdma);
            copy.setCellIdentity((CellIdentityTdscdma) rewritten);
            return copy;
        }
        svc.recordHookError(pointId, null,
                "Unsupported CellInfo type: " + info.getClass().getSimpleName());
        return null;
    }

    /**
     * Rebuilds {@code identity} from the original values merged with the {@code item} fields of
     * {@code decision}. Returns {@code null} when the identity can not be rebuilt safely.
     */
    @Nullable
    private static CellIdentity rewriteCellIdentity(CellIdentity identity,
            ArrayMap<String, Object> decision, ApiPolicyInternal svc, String pointId) {
        final Object rawItem = decision.get("item");
        // Allow "modify" with the fields at the top level as well.
        final ArrayMap<?, ?> map = (rawItem instanceof ArrayMap)
                ? (ArrayMap<?, ?>) rawItem
                : decision;
        final Schema schema = Schema.of(identity);
        if (schema == null) {
            svc.recordHookError(pointId, null,
                    "Unsupported CellIdentity type: " + identity.getClass().getSimpleName());
            return null;
        }
        return schema.build(map, identity);
    }

    // ------------------------------------------------------------------------------------
    // Flat key/value projection of telephony objects
    // ------------------------------------------------------------------------------------

    private static Object[] cellInfoToKv(CellInfo info) {
        final PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(12)
                .put("registered", info.isRegistered())
                .put("connection_status", (long) info.getCellConnectionStatus())
                .put("time_ms", info.getTimeStamp());
        final CellIdentity identity = info.getCellIdentity();
        if (identity != null) {
            b.put("identity", cellIdentityToKv(identity));
        }
        return b.build();
    }

    private static Object[] cellIdentityToKv(CellIdentity identity) {
        final Schema schema = Schema.of(identity);
        if (schema == null) {
            return new PolicyScriptEngine.KvBuilder(1).put("type", "unknown").build();
        }
        return schema.toKv(identity);
    }

    /** Per-RAT field schema: projection to Lua and rebuild from a merged decision. */
    private abstract static class Schema {
        abstract Object[] toKv(CellIdentity identity);

        abstract CellIdentity build(ArrayMap<?, ?> fields, CellIdentity original);

        /** Removes every identifying field (PLMN, area/identity, CSG, bands), keeping the type. */
        abstract CellIdentity strip(CellIdentity original);

        @Nullable
        static Schema of(CellIdentity identity) {
            if (identity instanceof CellIdentityLte) {
                return LTE;
            }
            if (identity instanceof CellIdentityGsm) {
                return GSM;
            }
            if (identity instanceof CellIdentityNr) {
                return NR;
            }
            if (identity instanceof CellIdentityWcdma) {
                return WCDMA;
            }
            if (identity instanceof CellIdentityCdma) {
                return CDMA;
            }
            if (identity instanceof CellIdentityTdscdma) {
                return TDSCDMA;
            }
            return null;
        }

        static String str(ArrayMap<?, ?> map, String key, @Nullable String fallback) {
            final Object raw = map.get(key);
            return (raw instanceof String s) ? s : fallback;
        }

        static int num(ArrayMap<?, ?> map, String key, int fallback) {
            final Object raw = map.get(key);
            if (raw instanceof Number n) {
                return n.intValue();
            }
            return fallback;
        }

        static long lng(ArrayMap<?, ?> map, String key, long fallback) {
            final Object raw = map.get(key);
            if (raw instanceof Number n) {
                return n.longValue();
            }
            return fallback;
        }

        static Collection<String> gsmPlmns(CellIdentity identity) {
            return (identity instanceof CellIdentityGsm gsm)
                    ? gsm.getAdditionalPlmns() : Collections.<String>emptyList();
        }

        static Collection<String> nrPlmns(CellIdentity identity) {
            return (identity instanceof CellIdentityNr nr)
                    ? nr.getAdditionalPlmns() : Collections.<String>emptyList();
        }

        static Collection<String> wcdmaPlmns(CellIdentity identity) {
            return (identity instanceof CellIdentityWcdma w)
                    ? w.getAdditionalPlmns() : Collections.<String>emptyList();
        }

        static Collection<String> tdscdmaPlmns(CellIdentity identity) {
            return (identity instanceof CellIdentityTdscdma t)
                    ? t.getAdditionalPlmns() : Collections.<String>emptyList();
        }

        static void putPlmn(PolicyScriptEngine.KvBuilder b, CellIdentity identity) {
            b.put("mcc", identity.getMccString());
            b.put("mnc", identity.getMncString());
        }
    }

    private static final Schema LTE = new Schema() {
        @Override
        Object[] toKv(CellIdentity identity) {
            final CellIdentityLte lte = (CellIdentityLte) identity;
            final PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(12)
                    .put("type", "lte")
                    .put("ci", (long) lte.getCi())
                    .put("pci", (long) lte.getPci())
                    .put("tac", (long) lte.getTac())
                    .put("earfcn", (long) lte.getEarfcn())
                    .put("bandwidth", (long) lte.getBandwidth());
            putPlmn(b, identity);
            return b.build();
        }

        @Override
        CellIdentity build(ArrayMap<?, ?> f, CellIdentity original) {
            final CellIdentityLte lte = (CellIdentityLte) original;
            return new CellIdentityLte(
                    num(f, "ci", lte.getCi()),
                    num(f, "pci", lte.getPci()),
                    num(f, "tac", lte.getTac()),
                    num(f, "earfcn", lte.getEarfcn()),
                    lte.getBands(),
                    num(f, "bandwidth", lte.getBandwidth()),
                    str(f, "mcc", lte.getMccString()),
                    str(f, "mnc", lte.getMncString()),
                    alphaLong(lte),
                    alphaShort(lte),
                    lte.getAdditionalPlmns(),
                    lte.getClosedSubscriberGroupInfo());
        }

        @Override
        CellIdentity strip(CellIdentity original) {
            return new CellIdentityLte(CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE, new int[] {},
                    CellInfo.UNAVAILABLE, null, null, null, null,
                    Collections.<String>emptyList(), null);
        }
    };

    private static final Schema GSM = new Schema() {
        @Override
        Object[] toKv(CellIdentity identity) {
            final CellIdentityGsm gsm = (CellIdentityGsm) identity;
            final PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(8)
                    .put("type", "gsm")
                    .put("lac", (long) gsm.getLac())
                    .put("cid", (long) gsm.getCid())
                    .put("arfcn", (long) gsm.getArfcn())
                    .put("bsic", (long) gsm.getBsic());
            putPlmn(b, identity);
            return b.build();
        }

        @Override
        CellIdentity build(ArrayMap<?, ?> f, CellIdentity original) {
            final CellIdentityGsm gsm = (CellIdentityGsm) original;
            return new CellIdentityGsm(
                    num(f, "lac", gsm.getLac()),
                    num(f, "cid", gsm.getCid()),
                    num(f, "arfcn", gsm.getArfcn()),
                    num(f, "bsic", gsm.getBsic()),
                    str(f, "mcc", gsm.getMccString()),
                    str(f, "mnc", gsm.getMncString()),
                    alphaLong(gsm),
                    alphaShort(gsm),
                    gsmPlmns(original));
        }

        @Override
        CellIdentity strip(CellIdentity original) {
            return new CellIdentityGsm(CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE, null, null, null, null,
                    Collections.<String>emptyList());
        }
    };

    private static final Schema NR = new Schema() {
        @Override
        Object[] toKv(CellIdentity identity) {
            final CellIdentityNr nr = (CellIdentityNr) identity;
            final PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(8)
                    .put("type", "nr")
                    .put("nci", nr.getNci())
                    .put("pci", (long) nr.getPci())
                    .put("tac", (long) nr.getTac())
                    .put("nrarfcn", (long) nr.getNrarfcn());
            putPlmn(b, identity);
            return b.build();
        }

        @Override
        CellIdentity build(ArrayMap<?, ?> f, CellIdentity original) {
            final CellIdentityNr nr = (CellIdentityNr) original;
            return new CellIdentityNr(
                    num(f, "pci", nr.getPci()),
                    num(f, "tac", nr.getTac()),
                    num(f, "nrarfcn", nr.getNrarfcn()),
                    nr.getBands(),
                    str(f, "mcc", nr.getMccString()),
                    str(f, "mnc", nr.getMncString()),
                    lng(f, "nci", nr.getNci()),
                    alphaLong(nr),
                    alphaShort(nr),
                    nrPlmns(original));
        }

        @Override
        CellIdentity strip(CellIdentity original) {
            return new CellIdentityNr(CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    CellInfo.UNAVAILABLE, new int[] {}, null, null, CellInfo.UNAVAILABLE,
                    null, null, Collections.<String>emptyList());
        }
    };

    private static final Schema WCDMA = new Schema() {
        @Override
        Object[] toKv(CellIdentity identity) {
            final CellIdentityWcdma w = (CellIdentityWcdma) identity;
            final PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(8)
                    .put("type", "wcdma")
                    .put("lac", (long) w.getLac())
                    .put("cid", (long) w.getCid())
                    .put("psc", (long) w.getPsc())
                    .put("uarfcn", (long) w.getUarfcn());
            putPlmn(b, identity);
            return b.build();
        }

        @Override
        CellIdentity build(ArrayMap<?, ?> f, CellIdentity original) {
            final CellIdentityWcdma w = (CellIdentityWcdma) original;
            return new CellIdentityWcdma(
                    num(f, "lac", w.getLac()),
                    num(f, "cid", w.getCid()),
                    num(f, "psc", w.getPsc()),
                    num(f, "uarfcn", w.getUarfcn()),
                    str(f, "mcc", w.getMccString()),
                    str(f, "mnc", w.getMncString()),
                    alphaLong(w),
                    alphaShort(w),
                    wcdmaPlmns(original),
                    w.getClosedSubscriberGroupInfo());
        }

        @Override
        CellIdentity strip(CellIdentity original) {
            return new CellIdentityWcdma(CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE, null, null, null, null,
                    Collections.<String>emptyList(), null);
        }
    };

    private static final Schema CDMA = new Schema() {
        @Override
        Object[] toKv(CellIdentity identity) {
            final CellIdentityCdma c = (CellIdentityCdma) identity;
            return new PolicyScriptEngine.KvBuilder(6)
                    .put("type", "cdma")
                    .put("nid", (long) c.getNetworkId())
                    .put("sid", (long) c.getSystemId())
                    .put("bid", (long) c.getBasestationId())
                    .put("latitude", (long) c.getLatitude())
                    .put("longitude", (long) c.getLongitude())
                    .build();
        }

        @Override
        CellIdentity build(ArrayMap<?, ?> f, CellIdentity original) {
            // CellIdentityCdma's public constructor ignores every argument and produces an
            // all-UNAVAILABLE identity, so a rewrite is not representable. Fail open instead of
            // silently blanking the identity.
            return null;
        }

        @Override
        CellIdentity strip(CellIdentity original) {
            return new CellIdentityCdma(CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    null, null);
        }
    };

    private static final Schema TDSCDMA = new Schema() {
        @Override
        Object[] toKv(CellIdentity identity) {
            final CellIdentityTdscdma t = (CellIdentityTdscdma) identity;
            final PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(8)
                    .put("type", "tdscdma")
                    .put("lac", (long) t.getLac())
                    .put("cid", (long) t.getCid())
                    .put("cpid", (long) t.getCpid())
                    .put("uarfcn", (long) t.getUarfcn());
            putPlmn(b, identity);
            return b.build();
        }

        @Override
        CellIdentity build(ArrayMap<?, ?> f, CellIdentity original) {
            final CellIdentityTdscdma t = (CellIdentityTdscdma) original;
            return new CellIdentityTdscdma(
                    str(f, "mcc", t.getMccString()),
                    str(f, "mnc", t.getMncString()),
                    num(f, "lac", t.getLac()),
                    num(f, "cid", t.getCid()),
                    num(f, "cpid", t.getCpid()),
                    num(f, "uarfcn", t.getUarfcn()),
                    alphaLong(t),
                    alphaShort(t),
                    tdscdmaPlmns(original),
                    t.getClosedSubscriberGroupInfo());
        }

        @Override
        CellIdentity strip(CellIdentity original) {
            return new CellIdentityTdscdma(null, null, CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE,
                    CellInfo.UNAVAILABLE, CellInfo.UNAVAILABLE, null, null,
                    Collections.<String>emptyList(), null);
        }
    };

    @Nullable
    private static String alphaLong(CellIdentity identity) {
        final CharSequence v = identity.getOperatorAlphaLong();
        return (v == null) ? null : v.toString();
    }

    @Nullable
    private static String alphaShort(CellIdentity identity) {
        final CharSequence v = identity.getOperatorAlphaShort();
        return (v == null) ? null : v.toString();
    }

    /** Removes the identity fields (PLMN, area, CSG); used when a script drops it. */
    @Nullable
    private static CellIdentity stripToPlmn(CellIdentity identity) {
        final Schema schema = Schema.of(identity);
        if (schema == null) {
            return null;
        }
        return schema.strip(identity);
    }

    private static void safeRecordUnexpectedError(
            @Nullable ApiPolicyInternal svc, String pointId, Throwable t) {
        Slog.e(TAG, "Unexpected exception in hook " + pointId, t);
        if (svc != null) {
            try {
                svc.recordHookError(pointId, null, "Unexpected hook exception: " + t);
            } catch (Throwable ignored) {
            }
        }
    }
}
