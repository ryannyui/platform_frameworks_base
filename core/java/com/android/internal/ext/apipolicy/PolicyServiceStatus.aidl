package com.android.internal.ext.apipolicy;

/**
 * Health and recovery status of the API policy service and its persistent store.
 *
 * @hide
 */
parcelable PolicyServiceStatus {
    boolean globallyDisabled;
    boolean storageHealthy;
    @nullable @utf8InCpp String storageError;
    int loadedScriptCount;
    int rejectedScriptCount;
}
