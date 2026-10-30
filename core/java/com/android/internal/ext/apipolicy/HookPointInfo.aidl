package com.android.internal.ext.apipolicy;

/**
 * Metadata and live runtime statistics of a registered API policy hook point.
 *
 * @hide
 */
parcelable HookPointInfo {
    @utf8InCpp String pointId;
    @utf8InCpp String category;
    @utf8InCpp String description;
    @utf8InCpp String[] boundScriptIds;
    long invokeCount;
    long modifyCount;
    long dropCount;
    long errorCount;
}
