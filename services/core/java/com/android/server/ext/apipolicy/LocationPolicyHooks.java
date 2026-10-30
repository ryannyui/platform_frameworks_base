package com.android.server.ext.apipolicy;

import static com.android.server.location.LocationPermissions.PERMISSION_COARSE;
import static com.android.server.location.LocationPermissions.PERMISSION_FINE;

import android.annotation.Nullable;
import android.location.Location;
import android.location.LocationResult;
import android.location.LocationResult.BadLocationException;
import android.location.util.identity.CallerIdentity;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.Slog;

import com.android.server.LocalServices;
import com.android.server.location.LocationPermissions.PermissionLevel;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Location hook points adapter bridging {@code LocationProviderManager} and
 * {@link ApiPolicyInternal}, exposing full {@link Location} fields and {@link Bundle} extras with
 * fail-open exception safety and batch {@link LocationResult} preservation.
 */
public final class LocationPolicyHooks {

    private static final String TAG = "LocationPolicyHooks";

    public static final String POINT_ON_REPORT_LOCATION = "location.on_report_location";
    public static final String POINT_ON_PROVIDER_TICK = "location.on_provider_tick";
    public static final String POINT_DELIVER_LOCATION = "location.deliver_location";
    public static final String POINT_GET_LAST_LOCATION = "location.get_last_location";

    private static final long MIN_TICK_DELAY_MS = 200L;
    private static final long DEFAULT_ZERO_INTERVAL_TICK_MS = 1000L;
    private static final long MAX_TICK_DELAY_MS = 60L * 60L * 1000L;

    public static final class ProviderTickOutcome {
        @Nullable public final LocationResult locationResult;
        public final long nextTickDelayMs;

        ProviderTickOutcome(@Nullable LocationResult locationResult, long nextTickDelayMs) {
            this.locationResult = locationResult;
            this.nextTickDelayMs = nextTickDelayMs;
        }
    }

    private static volatile ApiPolicyInternal sCachedService;
    private static final AtomicBoolean sBindingListenerRegistered = new AtomicBoolean(false);
    private static final CopyOnWriteArrayList<WeakReference<Runnable>> sTickObservers =
            new CopyOnWriteArrayList<>();

    private LocationPolicyHooks() {}

    @Nullable
    private static ApiPolicyInternal getService() {
        ApiPolicyInternal svc = sCachedService;
        if (svc == null) {
            svc = LocalServices.getService(ApiPolicyInternal.class);
            if (svc != null) {
                sCachedService = svc;
            }
        }
        if (svc != null && sBindingListenerRegistered.compareAndSet(false, true)) {
            svc.registerBindingChangeListener(LocationPolicyHooks::notifyTickObservers);
        }
        return svc;
    }

    static void registerHookPoints(ApiPolicyInternal service) {
        service.registerHookPoint(
                POINT_ON_REPORT_LOCATION,
                "location",
                "Passive hardware/provider location ingress in LocationProviderManager.onReportLocation");
        service.registerHookPoint(
                POINT_ON_PROVIDER_TICK,
                "location",
                "Active periodic location synthesis while provider request is active");
        service.registerHookPoint(
                POINT_DELIVER_LOCATION,
                "location",
                "Per-caller async location delivery in acceptLocationChange (continuous & single-shot)");
        service.registerHookPoint(
                POINT_GET_LAST_LOCATION,
                "location",
                "Per-caller sync cache pull in LocationProviderManager.getLastLocation");
    }

    /**
     * Registers a strongly-owned observer on {@code LocationProviderManager} (stored weakly here
     * to avoid retaining transient test managers) that wakes up when script bindings change.
     */
    public static void registerTickObserver(Runnable observer) {
        if (observer == null) {
            return;
        }
        try {
            sTickObservers.removeIf(ref -> ref.get() == null);
            sTickObservers.add(new WeakReference<>(observer));
            getService();
        } catch (Throwable t) {
            Slog.e(TAG, "Failed to register tick observer", t);
        }
    }

    private static void notifyTickObservers() {
        for (WeakReference<Runnable> ref : sTickObservers) {
            Runnable r = ref.get();
            if (r == null) {
                sTickObservers.remove(ref);
                continue;
            }
            try {
                r.run();
            } catch (Throwable t) {
                Slog.e(TAG, "Tick observer failed", t);
            }
        }
    }

    public static long defaultTickDelayMs(long requestIntervalMs) {
        if (requestIntervalMs <= 0L) {
            return DEFAULT_ZERO_INTERVAL_TICK_MS;
        }
        return clampTickDelayMs(requestIntervalMs);
    }

    private static long clampTickDelayMs(long delayMs) {
        if (delayMs < MIN_TICK_DELAY_MS) {
            return MIN_TICK_DELAY_MS;
        }
        if (delayMs > MAX_TICK_DELAY_MS) {
            return MAX_TICK_DELAY_MS;
        }
        return delayMs;
    }

    public static boolean isPointActive(String pointId) {
        try {
            ApiPolicyInternal svc = getService();
            return svc != null && svc.isPointActive(pointId);
        } catch (Throwable t) {
            Slog.e(TAG, "isPointActive failed for " + pointId, t);
            return false;
        }
    }

    @Nullable
    public static LocationResult onReportLocation(
            String provider, @Nullable LocationResult original) {
        if (original == null) {
            return null;
        }
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_ON_REPORT_LOCATION)) {
                return original;
            }

            final int size = original.size();
            if (size == 1) {
                Location baseLoc = original.get(0);
                Object[] ctx = new PolicyScriptEngine.KvBuilder(6)
                        .put("provider", provider)
                        .put("count", 1L)
                        .put("batch_index", 1L)
                        .put("has_original", Boolean.TRUE)
                        .put("location", locationToFlatKv(baseLoc))
                        .build();

                ArrayMap<String, Object> decision = svc.evaluate(POINT_ON_REPORT_LOCATION, ctx);
                if (decision == null) {
                    return original;
                }
                String action = getAction(decision);
                if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                    return null;
                }
                if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                    Location modified = buildModifiedLocation(
                            provider, baseLoc, decision, POINT_ON_REPORT_LOCATION, svc);
                    return (modified != null) ? LocationResult.wrap(modified) : original;
                }
                return original;
            }

            ArrayList<Location> outList = new ArrayList<>(size);
            boolean anyChanged = false;
            for (int i = 0; i < size; i++) {
                Location item = original.get(i);
                Object[] ctx = new PolicyScriptEngine.KvBuilder(6)
                        .put("provider", provider)
                        .put("count", (long) size)
                        .put("batch_index", (long) (i + 1))
                        .put("has_original", Boolean.TRUE)
                        .put("location", locationToFlatKv(item))
                        .build();

                ArrayMap<String, Object> decision = svc.evaluate(POINT_ON_REPORT_LOCATION, ctx);
                if (decision == null) {
                    outList.add(item);
                    continue;
                }
                String action = getAction(decision);
                if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                    anyChanged = true;
                    continue;
                }
                if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                    Location modified = buildModifiedLocation(
                            provider, item, decision, POINT_ON_REPORT_LOCATION, svc);
                    if (modified != null) {
                        outList.add(modified);
                        anyChanged = true;
                    } else {
                        outList.add(item);
                    }
                    continue;
                }
                outList.add(item);
            }

            if (!anyChanged) {
                return original;
            }
            if (outList.isEmpty()) {
                return null;
            }
            try {
                return LocationResult.wrap(outList).validate();
            } catch (BadLocationException e) {
                svc.recordHookError(POINT_ON_REPORT_LOCATION, null, e.getMessage());
                return original;
            }
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_ON_REPORT_LOCATION, t);
            return original;
        }
    }

    public static ProviderTickOutcome onProviderTick(
            String provider,
            long requestIntervalMs,
            int quality,
            long sinceLastReportMs,
            @Nullable Location cachedLocation) {
        long nextDelayMs = defaultTickDelayMs(requestIntervalMs);
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_ON_PROVIDER_TICK)) {
                return new ProviderTickOutcome(null, nextDelayMs);
            }

            PolicyScriptEngine.KvBuilder builder = new PolicyScriptEngine.KvBuilder(7)
                    .put("provider", provider)
                    .put("request_interval_ms", requestIntervalMs)
                    .put("quality", (long) quality)
                    .put("since_last_report_ms", sinceLastReportMs)
                    .put("has_original", cachedLocation != null);
            if (cachedLocation != null) {
                builder.put("location", locationToFlatKv(cachedLocation));
            }

            ArrayMap<String, Object> decision =
                    svc.evaluate(POINT_ON_PROVIDER_TICK, builder.build());
            if (decision == null) {
                return new ProviderTickOutcome(null, nextDelayMs);
            }

            Object customTickObj = decision.get("next_tick_ms");
            if (customTickObj instanceof Number n) {
                nextDelayMs = clampTickDelayMs(n.longValue());
            }

            String action = getAction(decision);
            if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                Location modified = buildModifiedLocation(
                        provider, cachedLocation, decision, POINT_ON_PROVIDER_TICK, svc);
                if (modified != null) {
                    return new ProviderTickOutcome(LocationResult.wrap(modified), nextDelayMs);
                }
            }
            return new ProviderTickOutcome(null, nextDelayMs);
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_ON_PROVIDER_TICK, t);
            return new ProviderTickOutcome(null, nextDelayMs);
        }
    }

    @Nullable
    public static LocationResult onDeliverLocation(
            String provider,
            CallerIdentity identity,
            @PermissionLevel int permissionLevel,
            long intervalMs,
            boolean isSingleShot,
            @Nullable LocationResult fineLocationResult) {
        if (fineLocationResult == null) {
            return null;
        }
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_DELIVER_LOCATION)) {
                return fineLocationResult;
            }

            final int size = fineLocationResult.size();
            if (size == 1) {
                Location baseLoc = fineLocationResult.get(0);
                Object[] ctx = buildDeliverLocationContext(
                        provider, identity, permissionLevel, intervalMs, isSingleShot,
                        1L, 1L, baseLoc);

                ArrayMap<String, Object> decision = svc.evaluate(POINT_DELIVER_LOCATION, ctx);
                if (decision == null) {
                    return fineLocationResult;
                }
                String action = getAction(decision);
                if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                    return null;
                }
                if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                    Location modified = buildModifiedLocation(
                            provider, baseLoc, decision, POINT_DELIVER_LOCATION, svc);
                    return (modified != null) ? LocationResult.wrap(modified) : fineLocationResult;
                }
                return fineLocationResult;
            }

            ArrayList<Location> outList = new ArrayList<>(size);
            boolean anyChanged = false;
            for (int i = 0; i < size; i++) {
                Location item = fineLocationResult.get(i);
                Object[] ctx = buildDeliverLocationContext(
                        provider, identity, permissionLevel, intervalMs, isSingleShot,
                        (long) size, (long) (i + 1), item);

                ArrayMap<String, Object> decision = svc.evaluate(POINT_DELIVER_LOCATION, ctx);
                if (decision == null) {
                    outList.add(item);
                    continue;
                }
                String action = getAction(decision);
                if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                    anyChanged = true;
                    continue;
                }
                if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                    Location modified = buildModifiedLocation(
                            provider, item, decision, POINT_DELIVER_LOCATION, svc);
                    if (modified != null) {
                        outList.add(modified);
                        anyChanged = true;
                    } else {
                        outList.add(item);
                    }
                    continue;
                }
                outList.add(item);
            }

            if (!anyChanged) {
                return fineLocationResult;
            }
            if (outList.isEmpty()) {
                return null;
            }
            try {
                return LocationResult.wrap(outList).validate();
            } catch (BadLocationException e) {
                svc.recordHookError(POINT_DELIVER_LOCATION, null, e.getMessage());
                return fineLocationResult;
            }
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_DELIVER_LOCATION, t);
            return fineLocationResult;
        }
    }

    @Nullable
    public static Location onGetLastLocation(
            String provider,
            CallerIdentity identity,
            @PermissionLevel int permissionLevel,
            @Nullable Location original) {
        ApiPolicyInternal svc = null;
        try {
            svc = getService();
            if (svc == null || !svc.isPointActive(POINT_GET_LAST_LOCATION)) {
                return original;
            }

            PolicyScriptEngine.KvBuilder builder = new PolicyScriptEngine.KvBuilder(10)
                    .put("provider", provider)
                    .put("uid", (long) identity.getUid())
                    .put("pid", (long) identity.getPid())
                    .put("user_id", (long) identity.getUserId())
                    .put("package_name", identity.getPackageName())
                    .put("attribution_tag", identity.getAttributionTag())
                    .put("permission_level", permissionLevelToString(permissionLevel))
                    .put("has_original", original != null);
            if (original != null) {
                builder.put("location", locationToFlatKv(original));
            }

            ArrayMap<String, Object> decision =
                    svc.evaluate(POINT_GET_LAST_LOCATION, builder.build());
            if (decision == null) {
                return original;
            }

            String action = getAction(decision);
            if (ApiPolicyInternal.ACTION_DROP.equals(action)) {
                return null;
            }
            if (ApiPolicyInternal.ACTION_MODIFY.equals(action)) {
                Location modified = buildModifiedLocation(
                        provider, original, decision, POINT_GET_LAST_LOCATION, svc);
                return (modified != null) ? modified : original;
            }
            return original;
        } catch (Throwable t) {
            safeRecordUnexpectedError(svc, POINT_GET_LAST_LOCATION, t);
            return original;
        }
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

    private static Object[] buildDeliverLocationContext(
            String provider,
            CallerIdentity identity,
            @PermissionLevel int permissionLevel,
            long intervalMs,
            boolean isSingleShot,
            long count,
            long batchIndex,
            Location loc) {
        PolicyScriptEngine.KvBuilder builder = new PolicyScriptEngine.KvBuilder(13)
                .put("provider", provider)
                .put("uid", (long) identity.getUid())
                .put("pid", (long) identity.getPid())
                .put("user_id", (long) identity.getUserId())
                .put("package_name", identity.getPackageName())
                .put("attribution_tag", identity.getAttributionTag())
                .put("permission_level", permissionLevelToString(permissionLevel))
                .put("is_single_shot", isSingleShot)
                .put("count", count)
                .put("batch_index", batchIndex)
                .put("has_original", Boolean.TRUE)
                .put("location", locationToFlatKv(loc));
        if (intervalMs >= 0) {
            builder.put("interval_ms", intervalMs);
        }
        return builder.build();
    }

    private static String permissionLevelToString(@PermissionLevel int level) {
        return switch (level) {
            case PERMISSION_FINE -> "fine";
            case PERMISSION_COARSE -> "coarse";
            default -> "none";
        };
    }

    private static String getAction(ArrayMap<String, Object> decision) {
        Object raw = decision.get("action");
        return (raw instanceof String s) ? s : ApiPolicyInternal.ACTION_ALLOW;
    }

    private static Object[] locationToFlatKv(Location loc) {
        PolicyScriptEngine.KvBuilder b = new PolicyScriptEngine.KvBuilder(18)
                .put("provider", loc.getProvider())
                .put("time_ms", loc.getTime())
                .put("elapsed_ns", loc.getElapsedRealtimeNanos())
                .put("latitude", loc.getLatitude())
                .put("longitude", loc.getLongitude())
                .put("is_mock", loc.isMock());

        if (loc.hasElapsedRealtimeUncertaintyNanos()) {
            b.put("elapsed_uncertainty_ns", loc.getElapsedRealtimeUncertaintyNanos());
        }
        if (loc.hasAccuracy()) {
            b.put("accuracy", (double) loc.getAccuracy());
        }
        if (loc.hasAltitude()) {
            b.put("altitude", loc.getAltitude());
        }
        if (loc.hasVerticalAccuracy()) {
            b.put("vertical_accuracy", (double) loc.getVerticalAccuracyMeters());
        }
        if (loc.hasSpeed()) {
            b.put("speed", (double) loc.getSpeed());
        }
        if (loc.hasSpeedAccuracy()) {
            b.put("speed_accuracy", (double) loc.getSpeedAccuracyMetersPerSecond());
        }
        if (loc.hasBearing()) {
            b.put("bearing", (double) loc.getBearing());
        }
        if (loc.hasBearingAccuracy()) {
            b.put("bearing_accuracy", (double) loc.getBearingAccuracyDegrees());
        }
        if (loc.hasMslAltitude()) {
            b.put("msl_altitude", loc.getMslAltitudeMeters());
        }
        if (loc.hasMslAltitudeAccuracy()) {
            b.put("msl_altitude_accuracy", (double) loc.getMslAltitudeAccuracyMeters());
        }

        try {
            Bundle extras = loc.getExtras();
            if (extras != null && !extras.isEmpty()) {
                Set<String> keys = extras.keySet();
                PolicyScriptEngine.KvBuilder eb = new PolicyScriptEngine.KvBuilder(keys.size());
                for (String k : keys) {
                    Object v = extras.get(k);
                    if (v instanceof String
                            || v instanceof Boolean
                            || v instanceof Integer
                            || v instanceof Long
                            || v instanceof Float
                            || v instanceof Double) {
                        eb.put(k, v);
                    }
                }
                b.put("extras", eb.build());
            }
        } catch (Throwable t) {
            Slog.w(TAG, "Ignoring unreadable Location extras bundle", t);
        }
        return b.build();
    }

    @SuppressWarnings("unchecked")
    @Nullable
    private static Location buildModifiedLocation(
            String defaultProvider,
            @Nullable Location original,
            ArrayMap<String, Object> decision,
            String pointId,
            ApiPolicyInternal svc) {
        ArrayMap<String, Object> fields = decision;
        Object nestedLoc = decision.get("location");
        if (nestedLoc instanceof ArrayMap<?, ?> nestedMap) {
            fields = (ArrayMap<String, Object>) nestedMap;
        }

        // Clone original if present; otherwise create a blank Location with NO implicit timestamps
        // or extras — every required field (time_ms, elapsed_ns, accuracy, lat/lon) must be
        // explicitly provided by the user's Lua script.
        Location out = (original != null) ? new Location(original) : new Location(defaultProvider);

        Object providerVal = fields.get("provider");
        if (providerVal instanceof String p && !p.isEmpty()) {
            out.setProvider(p);
        }

        Object timeMsVal = fields.get("time_ms");
        if (timeMsVal instanceof Number n) {
            out.setTime(n.longValue());
        }

        Object elapsedNsVal = fields.get("elapsed_ns");
        if (elapsedNsVal instanceof Number n) {
            out.setElapsedRealtimeNanos(n.longValue());
        }

        if (fields.containsKey("elapsed_uncertainty_ns")) {
            Object v = fields.get("elapsed_uncertainty_ns");
            if (Boolean.FALSE.equals(v)) {
                out.removeElapsedRealtimeUncertaintyNanos();
            } else if (v instanceof Number n) {
                double dv = n.doubleValue();
                if (!Double.isFinite(dv) || dv < 0.0) {
                    svc.recordHookError(pointId, null, "Invalid elapsed_uncertainty_ns: " + dv);
                    return null;
                }
                out.setElapsedRealtimeUncertaintyNanos(dv);
            }
        }

        Object latVal = fields.get("latitude");
        if (latVal instanceof Number n) {
            double dv = n.doubleValue();
            if (!Double.isFinite(dv)) {
                svc.recordHookError(pointId, null, "Non-finite latitude: " + dv);
                return null;
            }
            out.setLatitude(dv);
        }

        Object lonVal = fields.get("longitude");
        if (lonVal instanceof Number n) {
            double dv = n.doubleValue();
            if (!Double.isFinite(dv)) {
                svc.recordHookError(pointId, null, "Non-finite longitude: " + dv);
                return null;
            }
            out.setLongitude(dv);
        }

        if (fields.containsKey("accuracy")) {
            Object v = fields.get("accuracy");
            if (Boolean.FALSE.equals(v)) {
                out.removeAccuracy();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv) || fv < 0.0f) {
                    svc.recordHookError(pointId, null, "Invalid accuracy: " + fv);
                    return null;
                }
                out.setAccuracy(fv);
            }
        }

        if (fields.containsKey("altitude")) {
            Object v = fields.get("altitude");
            if (Boolean.FALSE.equals(v)) {
                out.removeAltitude();
            } else if (v instanceof Number n) {
                double dv = n.doubleValue();
                if (!Double.isFinite(dv)) {
                    svc.recordHookError(pointId, null, "Non-finite altitude: " + dv);
                    return null;
                }
                out.setAltitude(dv);
            }
        }

        if (fields.containsKey("vertical_accuracy")) {
            Object v = fields.get("vertical_accuracy");
            if (Boolean.FALSE.equals(v)) {
                out.removeVerticalAccuracy();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv) || fv < 0.0f) {
                    svc.recordHookError(pointId, null, "Invalid vertical_accuracy: " + fv);
                    return null;
                }
                out.setVerticalAccuracyMeters(fv);
            }
        }

        if (fields.containsKey("speed")) {
            Object v = fields.get("speed");
            if (Boolean.FALSE.equals(v)) {
                out.removeSpeed();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv) || fv < 0.0f) {
                    svc.recordHookError(pointId, null, "Invalid speed: " + fv);
                    return null;
                }
                out.setSpeed(fv);
            }
        }

        if (fields.containsKey("speed_accuracy")) {
            Object v = fields.get("speed_accuracy");
            if (Boolean.FALSE.equals(v)) {
                out.removeSpeedAccuracy();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv) || fv < 0.0f) {
                    svc.recordHookError(pointId, null, "Invalid speed_accuracy: " + fv);
                    return null;
                }
                out.setSpeedAccuracyMetersPerSecond(fv);
            }
        }

        if (fields.containsKey("bearing")) {
            Object v = fields.get("bearing");
            if (Boolean.FALSE.equals(v)) {
                out.removeBearing();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv)) {
                    svc.recordHookError(pointId, null, "Non-finite bearing: " + fv);
                    return null;
                }
                out.setBearing(fv);
            }
        }

        if (fields.containsKey("bearing_accuracy")) {
            Object v = fields.get("bearing_accuracy");
            if (Boolean.FALSE.equals(v)) {
                out.removeBearingAccuracy();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv) || fv < 0.0f) {
                    svc.recordHookError(pointId, null, "Invalid bearing_accuracy: " + fv);
                    return null;
                }
                out.setBearingAccuracyDegrees(fv);
            }
        }

        if (fields.containsKey("msl_altitude")) {
            Object v = fields.get("msl_altitude");
            if (Boolean.FALSE.equals(v)) {
                out.removeMslAltitude();
            } else if (v instanceof Number n) {
                double dv = n.doubleValue();
                if (!Double.isFinite(dv)) {
                    svc.recordHookError(pointId, null, "Non-finite msl_altitude: " + dv);
                    return null;
                }
                out.setMslAltitudeMeters(dv);
            }
        }

        if (fields.containsKey("msl_altitude_accuracy")) {
            Object v = fields.get("msl_altitude_accuracy");
            if (Boolean.FALSE.equals(v)) {
                out.removeMslAltitudeAccuracy();
            } else if (v instanceof Number n) {
                float fv = n.floatValue();
                if (!Float.isFinite(fv) || fv < 0.0f) {
                    svc.recordHookError(pointId, null, "Invalid msl_altitude_accuracy: " + fv);
                    return null;
                }
                out.setMslAltitudeAccuracyMeters(fv);
            }
        }

        Object isMockVal = fields.get("is_mock");
        if (isMockVal instanceof Boolean b) {
            out.setMock(b);
        }

        if (fields.containsKey("extras")) {
            Object extrasObj = fields.get("extras");
            if (Boolean.FALSE.equals(extrasObj)) {
                out.setExtras(null);
            } else if (extrasObj instanceof ArrayMap<?, ?> extrasMap) {
                Bundle bundle = buildExplicitExtrasBundle((ArrayMap<String, Object>) extrasMap);
                out.setExtras(bundle.isEmpty() ? null : bundle);
            }
        }

        if (!out.isComplete()) {
            svc.recordHookError(
                    pointId,
                    null,
                    "Incomplete Location (script must explicitly provide provider, accuracy, "
                            + "non-zero time_ms, and non-zero elapsed_ns)");
            return null;
        }

        try {
            LocationResult.wrap(out).validate();
        } catch (BadLocationException e) {
            svc.recordHookError(pointId, null, e.getMessage());
            return null;
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Bundle buildExplicitExtrasBundle(ArrayMap<String, Object> extrasMap) {
        Bundle b = new Bundle(extrasMap.size());
        for (Map.Entry<String, Object> entry : extrasMap.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if (key == null || val == null) {
                continue;
            }
            if (val instanceof ArrayMap<?, ?> typedSpec) {
                putTypedBundleEntry(b, key, (ArrayMap<String, Object>) typedSpec);
            } else if (val instanceof Boolean boolVal) {
                b.putBoolean(key, boolVal);
            } else if (val instanceof String strVal) {
                b.putString(key, strVal);
            } else if (val instanceof Long longVal) {
                long lv = longVal;
                if (lv >= Integer.MIN_VALUE && lv <= Integer.MAX_VALUE) {
                    b.putInt(key, (int) lv);
                } else {
                    b.putLong(key, lv);
                }
            } else if (val instanceof Number numVal) {
                b.putDouble(key, numVal.doubleValue());
            }
        }
        return b;
    }

    private static void putTypedBundleEntry(
            Bundle b, String key, ArrayMap<String, Object> typedSpec) {
        Object typeObj = typedSpec.get("type");
        Object valueObj = typedSpec.get("value");
        if (!(typeObj instanceof String type) || valueObj == null) {
            return;
        }
        switch (type) {
            case "int" -> {
                if (valueObj instanceof Number n) {
                    b.putInt(key, n.intValue());
                }
            }
            case "long" -> {
                if (valueObj instanceof Number n) {
                    b.putLong(key, n.longValue());
                }
            }
            case "float" -> {
                if (valueObj instanceof Number n) {
                    b.putFloat(key, n.floatValue());
                }
            }
            case "double" -> {
                if (valueObj instanceof Number n) {
                    b.putDouble(key, n.doubleValue());
                }
            }
            case "bool", "boolean" -> {
                if (valueObj instanceof Boolean bv) {
                    b.putBoolean(key, bv);
                }
            }
            case "string" -> {
                if (valueObj instanceof String sv) {
                    b.putString(key, sv);
                }
            }
            default -> {}
        }
    }
}
