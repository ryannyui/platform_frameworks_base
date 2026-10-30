package com.android.internal.ext.apipolicy;

/**
 * Metadata, source, and live runtime status of a deployed policy script.
 *
 * @hide
 */
parcelable PolicyScriptInfo {
    @utf8InCpp String scriptId;
    boolean enabled;
    @utf8InCpp String source;
    @utf8InCpp String[] registeredPoints;
    long invokeCount;
    long errorCount;
    long lastEvalMicros;
    @nullable @utf8InCpp String lastError;
    long updatedAtMs;
}
