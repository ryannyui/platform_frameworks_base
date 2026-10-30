package com.android.server.ext.apipolicy;

import android.annotation.Nullable;
import android.util.ArrayMap;

import com.android.server.utils.LazyJniRegistrar;
import com.android.tools.r8.keepanno.annotations.KeepItemKind;
import com.android.tools.r8.keepanno.annotations.MethodAccessFlags;
import com.android.tools.r8.keepanno.annotations.UsedByNative;

import java.util.ArrayList;
import java.util.List;

/**
 * JNI bridge and flat key-value marshaling utilities for the sandboxed Lua 5.4 runtime.
 */
@UsedByNative(
        description = "Referenced from JNI in"
                + " jni/com_android_server_ext_apipolicy_PolicyScriptEngine.cpp",
        kind = KeepItemKind.CLASS_AND_MEMBERS,
        methodAccess = {MethodAccessFlags.NATIVE})
public final class PolicyScriptEngine {

    static {
        LazyJniRegistrar.registerApiPolicyEngine();
    }

    private PolicyScriptEngine() {}

    static native long nativeCompileScript(
            String scriptId,
            String source,
            long maxMemBytes,
            int maxInitSteps,
            List<String> outRegisteredPoints,
            List<String> outInitLogs,
            String[] errorOut);

    @Nullable
    static native Object[] nativeInvokeHandler(
            long handle,
            String pointId,
            @Nullable Object[] inputFlatKv,
            int maxEvalSteps,
            List<String> logsOut,
            String[] errorOut);

    static native void nativeDestroyScript(long handle);

    /**
     * Converts an alternating {@code [String key, Object value, ...]} array returned from JNI
     * into a nested {@link ArrayMap}.
     */
    @Nullable
    public static ArrayMap<String, Object> flatKvToMap(@Nullable Object[] flatKv) {
        if (flatKv == null) {
            return null;
        }
        final int len = flatKv.length;
        ArrayMap<String, Object> map = new ArrayMap<>(len / 2);
        for (int i = 0; i + 1 < len; i += 2) {
            Object rawKey = flatKv[i];
            if (!(rawKey instanceof String key)) {
                continue;
            }
            Object rawVal = flatKv[i + 1];
            if (rawVal instanceof Object[] nested) {
                map.put(key, flatKvToMap(nested));
            } else if (rawVal != null) {
                map.put(key, rawVal);
            }
        }
        return map;
    }

    /**
     * Helper builder for constructing alternating {@code Object[]} flat key-value tables for JNI.
     */
    public static final class KvBuilder {
        private final ArrayList<Object> mItems;

        public KvBuilder(int expectedPairs) {
            mItems = new ArrayList<>(expectedPairs * 2);
        }

        public KvBuilder put(String key, @Nullable Object value) {
            if (key != null && value != null) {
                mItems.add(key);
                mItems.add(value);
            }
            return this;
        }

        public Object[] build() {
            return mItems.toArray();
        }
    }
}
