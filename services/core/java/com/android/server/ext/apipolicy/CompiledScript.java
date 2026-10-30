package com.android.server.ext.apipolicy;

import android.annotation.Nullable;
import android.os.SystemClock;
import android.util.ArrayMap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Reference-counted, thread-safe wrapper around a compiled native Lua 5.4 VM instance.
 */
final class CompiledScript {

    static final int CIRCUIT_BREAKER_THRESHOLD = 20;

    final String scriptId;
    final List<String> registeredPoints;

    private final ReentrantLock mVmLock = new ReentrantLock();
    private final AtomicInteger mRefCount = new AtomicInteger(1);
    private long mNativeHandle;

    final AtomicLong invokeCount = new AtomicLong(0);
    final AtomicLong errorCount = new AtomicLong(0);
    final AtomicInteger consecutiveErrors = new AtomicInteger(0);
    final AtomicLong lastEvalMicros = new AtomicLong(0);
    volatile String lastError;

    static final class EvalOutcome {
        @Nullable final ArrayMap<String, Object> decision;
        final List<String> logs;
        @Nullable final String error;
        final boolean tripCircuitBreaker;

        EvalOutcome(
                @Nullable ArrayMap<String, Object> decision,
                List<String> logs,
                @Nullable String error,
                boolean tripCircuitBreaker) {
            this.decision = decision;
            this.logs = logs;
            this.error = error;
            this.tripCircuitBreaker = tripCircuitBreaker;
        }
    }

    CompiledScript(String scriptId, long nativeHandle, List<String> points) {
        this.scriptId = scriptId;
        this.mNativeHandle = nativeHandle;
        this.registeredPoints = Collections.unmodifiableList(new ArrayList<>(points));
    }

    boolean tryAcquire() {
        while (true) {
            int cur = mRefCount.get();
            if (cur <= 0) {
                return false;
            }
            if (mRefCount.compareAndSet(cur, cur + 1)) {
                return true;
            }
        }
    }

    void release() {
        int remaining = mRefCount.decrementAndGet();
        if (remaining == 0) {
            destroyNative();
        }
    }

    /**
     * Releases the primary ownership reference held by {@link ApiPolicyManagerService}.
     */
    void releaseOwner() {
        release();
    }

    @Nullable
    EvalOutcome invoke(String pointId, @Nullable Object[] inputFlatKv, int maxEvalSteps) {
        if (!tryAcquire()) {
            return null;
        }
        try {
            ArrayList<String> logs = new ArrayList<>(4);
            String[] errorOut = new String[1];
            long startNs = SystemClock.elapsedRealtimeNanos();
            try {
                Object[] rawResult;
                mVmLock.lock();
                try {
                    if (mNativeHandle == 0) {
                        return null;
                    }
                    rawResult = PolicyScriptEngine.nativeInvokeHandler(
                            mNativeHandle, pointId, inputFlatKv, maxEvalSteps, logs, errorOut);
                } finally {
                    mVmLock.unlock();
                }

                long elapsedUs = (SystemClock.elapsedRealtimeNanos() - startNs) / 1000L;
                lastEvalMicros.set(elapsedUs);
                invokeCount.incrementAndGet();

                if (errorOut[0] != null) {
                    errorCount.incrementAndGet();
                    lastError = errorOut[0];
                    int streak = consecutiveErrors.incrementAndGet();
                    boolean trip = streak >= CIRCUIT_BREAKER_THRESHOLD;
                    return new EvalOutcome(null, logs, errorOut[0], trip);
                }

                consecutiveErrors.set(0);
                lastError = null;
                ArrayMap<String, Object> map = PolicyScriptEngine.flatKvToMap(rawResult);
                return new EvalOutcome(map, logs, null, false);
            } catch (Throwable t) {
                errorCount.incrementAndGet();
                String msg = "Unexpected invoke failure: " + t;
                lastError = msg;
                int streak = consecutiveErrors.incrementAndGet();
                boolean trip = streak >= CIRCUIT_BREAKER_THRESHOLD;
                return new EvalOutcome(null, logs, msg, trip);
            }
        } finally {
            release();
        }
    }

    private void destroyNative() {
        mVmLock.lock();
        try {
            long handle = mNativeHandle;
            mNativeHandle = 0;
            if (handle != 0) {
                PolicyScriptEngine.nativeDestroyScript(handle);
            }
        } finally {
            mVmLock.unlock();
        }
    }
}
