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

package android.ext.apipolicy;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.SystemApi;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;

import com.android.internal.ext.apipolicy.IApiPolicyManager;

/**
 * Client for the runtime API policy engine, for system components that live outside of
 * {@code system_server} (Bluetooth, telephony) or that are built with a restricted SDK surface.
 *
 * <p>The engine evaluates sandboxed Lua scripts bound to hook points. A component that hooks an
 * app-visible API calls {@link #isPointActive(String)} first: when no script binds the point the
 * only cost is one cached call and the component keeps its original behaviour untouched. When a
 * script is bound, the component passes the current object as a flat key/value {@link Bundle} and
 * gets back either {@code null} (keep the original) or a decision bundle whose
 * {@link #KEY_ACTION} is one of {@link #ACTION_ALLOW}, {@link #ACTION_DROP} or
 * {@link #ACTION_MODIFY}.
 *
 * <p>Only a small allowlist of system UIDs may call this API; the service enforces it.
 *
 * @hide
 */
@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
public final class ApiPolicyEvaluator {

    private static final String TAG = "ApiPolicyEvaluator";

    /** Service name the policy engine publishes. */
    public static final String SERVICE_NAME = "apipolicy";

    private static final String KEY_ACTION = "action";
    private static final String ACTION_ALLOW = "allow";
    private static final String ACTION_DROP = "drop";
    private static final String ACTION_MODIFY = "modify";

    /**
     * Bindings can only change when a script is applied, enabled, disabled or removed, all of
     * which are rare. A short TTL keeps the hot delivery path free of binder calls without
     * needing a push channel.
     */
    private static final long POINT_ACTIVE_TTL_MS = 500L;

    private static final class ActiveCacheEntry {
        final boolean active;
        final long expiresAtMs;

        ActiveCacheEntry(boolean active, long expiresAtMs) {
            this.active = active;
            this.expiresAtMs = expiresAtMs;
        }
    }

    private static final java.util.concurrent.ConcurrentHashMap<String, ActiveCacheEntry>
            sActiveCache = new java.util.concurrent.ConcurrentHashMap<>();

    private static volatile IApiPolicyManager sService;
    private static volatile long sUnavailableUntilMs;

    private ApiPolicyEvaluator() {}

    /**
     * Returns {@code true} when at least one enabled script binds {@code pointId}.
     *
     * <p>Cheap enough to call on every delivery: the result is served from
     * {@code system_server} memory and callers are expected to cache it and refresh on a bind
     * change notification.
     */
    public static boolean isPointActive(@NonNull String pointId) {
        final long now = android.os.SystemClock.elapsedRealtime();
        final ActiveCacheEntry cached = sActiveCache.get(pointId);
        if (cached != null && cached.expiresAtMs > now) {
            return cached.active;
        }
        final IApiPolicyManager service = getService();
        if (service == null) {
            return false;
        }
        final boolean active;
        try {
            active = service.isPointActiveForClient(pointId);
        } catch (RemoteException e) {
            Log.w(TAG, "isPointActive failed for " + pointId, e);
            sService = null;
            sActiveCache.clear();
            return false;
        } catch (RuntimeException e) {
            Log.w(TAG, "isPointActive failed for " + pointId, e);
            return false;
        }
        sActiveCache.put(pointId, new ActiveCacheEntry(active, now + POINT_ACTIVE_TTL_MS));
        return active;
    }

    /** Drops the cached binding state, for tests and after a service restart. */
    public static void invalidatePointActiveCache() {
        sActiveCache.clear();
        sService = null;
        sUnavailableUntilMs = 0L;
    }

    /**
     * Evaluates the scripts bound to {@code pointId} for one object.
     *
     * @param context flat key/value context, the same shape the in-process hooks use
     * @return the decision, or an empty bundle when the caller should keep the original object
     */
    @NonNull
    public static Bundle evaluate(@NonNull String pointId, @NonNull Bundle context) {
        final IApiPolicyManager service = getService();
        if (service == null) {
            return Bundle.EMPTY;
        }
        try {
            final Bundle decision = service.evaluateForClient(pointId, context);
            return (decision != null) ? decision : Bundle.EMPTY;
        } catch (RemoteException e) {
            Log.w(TAG, "evaluate failed for " + pointId, e);
            sService = null;
            sActiveCache.clear();
            return Bundle.EMPTY;
        } catch (RuntimeException e) {
            Log.w(TAG, "evaluate failed for " + pointId, e);
            return Bundle.EMPTY;
        }
    }

    /** Returns the action of a decision; an empty decision is "allow". */
    @NonNull
    public static String getAction(@NonNull Bundle decision) {
        final String action = decision.getString(KEY_ACTION);
        return (action != null) ? action : ACTION_ALLOW;
    }

    /** Returns {@code true} when the script asked for the object to be suppressed. */
    public static boolean isDrop(@NonNull Bundle decision) {
        return ACTION_DROP.equals(getAction(decision));
    }

    /** Returns {@code true} when the script supplied replacement fields. */
    public static boolean isModify(@NonNull Bundle decision) {
        return ACTION_MODIFY.equals(getAction(decision));
    }

    @Nullable
    private static IApiPolicyManager getService() {
        IApiPolicyManager service = sService;
        if (service != null) {
            return service;
        }
        if (sUnavailableUntilMs > android.os.SystemClock.elapsedRealtime()) {
            return null;
        }
        synchronized (ApiPolicyEvaluator.class) {
            service = sService;
            if (service == null && sUnavailableUntilMs
                    <= android.os.SystemClock.elapsedRealtime()) {
                final IBinder binder = ServiceManager.getService(SERVICE_NAME);
                if (binder == null) {
                    // The policy service is not published yet (or not shipped); retry later.
                    sUnavailableUntilMs = android.os.SystemClock.elapsedRealtime() + 5_000L;
                    return null;
                }
                service = IApiPolicyManager.Stub.asInterface(binder);
                sService = service;
            }
        }
        return service;
    }
}
