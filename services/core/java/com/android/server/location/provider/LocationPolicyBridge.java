package com.android.server.location.provider;

import static android.location.LocationManager.FUSED_PROVIDER;

import static com.android.server.location.LocationPermissions.PERMISSION_FINE;

import static java.lang.Math.max;

import android.annotation.Nullable;
import android.location.Location;
import android.location.LocationResult;
import android.location.provider.ProviderRequest;
import android.location.util.identity.CallerIdentity;
import android.os.Handler;
import android.os.SystemClock;
import android.os.UserHandle;

import com.android.internal.annotations.GuardedBy;
import com.android.server.FgThread;
import com.android.server.ext.apipolicy.LocationPolicyHooks;
import com.android.server.location.LocationPermissions.PermissionLevel;

import java.util.function.BooleanSupplier;

/**
 * Per-{@link LocationProviderManager} adapter for runtime API policy hooks.
 *
 * <p>Keeps all policy-related state (such as the provider tick scheduler) out of
 * {@link LocationProviderManager} so that the upstream class only needs single-line call sites.
 * Hooks are skipped for mock providers, and ingress/tick hooks are additionally skipped for the
 * passive provider.
 */
final class LocationPolicyBridge {

    private static final long FUSED_INITIAL_TICK_DELAY_MS = 50L;

    private final LocationProviderManager mManager;
    private final Object mLock;
    private final BooleanSupplier mIsStarted;
    private final boolean mIsPassive;

    private final Runnable mBindingsObserver = this::onBindingsChanged;
    private final Runnable mTickRunnable = this::onTick;

    @GuardedBy("mLock")
    private boolean mObserverRegistered = false;

    @GuardedBy("mLock")
    private boolean mTickScheduled = false;

    @GuardedBy("mLock")
    private long mTickDeadlineRealtimeMs = Long.MAX_VALUE;

    @GuardedBy("mLock")
    private long mLastRealReportRealtimeMs = 0L;

    /** Set while a tick-synthesized location is re-entering {@code onReportLocation}. */
    @GuardedBy("mLock")
    private boolean mInjecting = false;

    LocationPolicyBridge(LocationProviderManager manager, Object lock, BooleanSupplier isStarted) {
        mManager = manager;
        mLock = lock;
        mIsStarted = isStarted;
        mIsPassive = manager instanceof PassiveLocationProviderManager;
    }

    private boolean isMock() {
        return mManager.mProvider.isMock();
    }

    private String getName() {
        return mManager.mName;
    }

    // ---- delivery / query hooks ----

    /** Continuous delivery hook. Returns {@code null} if the delivery should be dropped. */
    @Nullable
    LocationResult onDeliver(CallerIdentity identity, @PermissionLevel int permissionLevel,
            long intervalMs, @Nullable LocationResult fineLocationResult) {
        if (fineLocationResult == null || isMock()) {
            return fineLocationResult;
        }
        return LocationPolicyHooks.onDeliverLocation(getName(), identity, permissionLevel,
                intervalMs, /* isSingleShot= */ false, fineLocationResult);
    }

    /** Single-shot ({@code getCurrentLocation}) delivery hook. */
    @Nullable
    LocationResult onDeliverSingleShot(CallerIdentity identity,
            @PermissionLevel int permissionLevel, @Nullable LocationResult fineLocationResult) {
        if (fineLocationResult == null || isMock()
                || !LocationPolicyHooks.isPointActive(LocationPolicyHooks.POINT_DELIVER_LOCATION)) {
            return fineLocationResult;
        }
        // single-shot listeners only ever receive the last location of a batch
        return LocationPolicyHooks.onDeliverLocation(getName(), identity, permissionLevel,
                /* intervalMs= */ -1L, /* isSingleShot= */ true,
                fineLocationResult.asLastLocationResult());
    }

    /** {@code getLastLocation} hook. */
    @Nullable
    Location onGetLastLocation(CallerIdentity identity, @PermissionLevel int permissionLevel,
            @Nullable Location location) {
        if (isMock()) {
            return location;
        }
        return LocationPolicyHooks.onGetLastLocation(getName(), identity, permissionLevel,
                location);
    }

    // ---- provider ingress ----

    /**
     * Provider ingress hook, called at the start of
     * {@link LocationProviderManager#onReportLocation}. Returns {@code null} if the report should
     * be dropped.
     */
    @GuardedBy("mLock")
    @Nullable
    LocationResult onReportLocationLocked(LocationResult locationResult) {
        if (mInjecting) {
            // synthesized by onTick(), already evaluated by policy
            return locationResult;
        }

        if (!mIsPassive && !isMock()) {
            locationResult = LocationPolicyHooks.onReportLocation(getName(), locationResult);
            if (locationResult == null) {
                return null;
            }
        }

        mLastRealReportRealtimeMs = SystemClock.elapsedRealtime();
        if (mTickScheduled) {
            scheduleTickLocked(LocationPolicyHooks.defaultTickDelayMs(
                    mManager.mProvider.getCurrentRequest().getIntervalMillis()));
        }
        return locationResult;
    }

    // ---- provider tick ----

    /**
     * Must be called whenever the manager state, mock state or provider request changes, so the
     * tick scheduler can be started or stopped accordingly.
     */
    @GuardedBy("mLock")
    void onStateChangedLocked() {
        if (mIsPassive) {
            return;
        }
        if (!mObserverRegistered && mIsStarted.getAsBoolean()) {
            mObserverRegistered = true;
            LocationPolicyHooks.registerTickObserver(mBindingsObserver);
        }
        updateTickLocked();
    }

    @GuardedBy("mLock")
    private boolean shouldTickLocked() {
        return mIsStarted.getAsBoolean()
                && !mIsPassive
                && !isMock()
                && mManager.mProvider.getCurrentRequest().isActive()
                && LocationPolicyHooks.isPointActive(LocationPolicyHooks.POINT_ON_PROVIDER_TICK);
    }

    private void onBindingsChanged() {
        synchronized (mLock) {
            if (!mIsStarted.getAsBoolean()) {
                return;
            }
            updateTickLocked();
        }
    }

    @GuardedBy("mLock")
    private void updateTickLocked() {
        if (!shouldTickLocked()) {
            if (mTickScheduled) {
                mTickScheduled = false;
                mTickDeadlineRealtimeMs = Long.MAX_VALUE;
                FgThread.getHandler().removeCallbacks(mTickRunnable);
            }
            return;
        }

        long initialDelayMs = FUSED_PROVIDER.equals(getName()) ? FUSED_INITIAL_TICK_DELAY_MS : 0L;
        if (!mTickScheduled) {
            scheduleTickLocked(initialDelayMs);
        } else {
            long targetIntervalMs = LocationPolicyHooks.defaultTickDelayMs(
                    mManager.mProvider.getCurrentRequest().getIntervalMillis());
            if (SystemClock.elapsedRealtime() + targetIntervalMs < mTickDeadlineRealtimeMs) {
                scheduleTickLocked(initialDelayMs);
            }
        }
    }

    @GuardedBy("mLock")
    private void scheduleTickLocked(long delayMs) {
        Handler handler = FgThread.getHandler();
        handler.removeCallbacks(mTickRunnable);
        long clampedDelayMs = max(0L, delayMs);
        mTickScheduled = true;
        mTickDeadlineRealtimeMs = SystemClock.elapsedRealtime() + clampedDelayMs;
        handler.postDelayed(mTickRunnable, clampedDelayMs);
    }

    private void onTick() {
        synchronized (mLock) {
            mTickScheduled = false;
            mTickDeadlineRealtimeMs = Long.MAX_VALUE;

            if (!shouldTickLocked()) {
                return;
            }

            ProviderRequest currentRequest = mManager.mProvider.getCurrentRequest();
            long sinceLastRealMs = (mLastRealReportRealtimeMs > 0L)
                    ? max(0L, SystemClock.elapsedRealtime() - mLastRealReportRealtimeMs)
                    : -1L;
            Location cached = mManager.getLastLocationUnsafe(
                    UserHandle.USER_ALL,
                    PERMISSION_FINE,
                    /* isBypass= */ true,
                    Long.MAX_VALUE);

            LocationPolicyHooks.ProviderTickOutcome outcome =
                    LocationPolicyHooks.onProviderTick(
                            getName(),
                            currentRequest.getIntervalMillis(),
                            currentRequest.getQuality(),
                            sinceLastRealMs,
                            cached);

            if (outcome.locationResult != null) {
                mInjecting = true;
                try {
                    mManager.onReportLocation(outcome.locationResult);
                } finally {
                    mInjecting = false;
                }
            }

            if (shouldTickLocked()) {
                scheduleTickLocked(outcome.nextTickDelayMs);
            }
        }
    }
}
