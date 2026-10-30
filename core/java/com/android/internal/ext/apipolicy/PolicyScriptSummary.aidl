package com.android.internal.ext.apipolicy;

/**
 * Metadata and live runtime status of a deployed policy script, excluding its source.
 *
 * @hide
 */
parcelable PolicyScriptSummary {
    @utf8InCpp String scriptId;
    boolean enabled;
    @utf8InCpp String[] registeredPoints;
    long invokeCount;
    long errorCount;
    long lastEvalMicros;
    @nullable @utf8InCpp String lastError;
    long updatedAtMs;
}
