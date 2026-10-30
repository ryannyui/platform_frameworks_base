package com.android.internal.ext.apipolicy;

/**
 * Result of validating or compiling a policy script.
 *
 * @hide
 */
parcelable ValidationResult {
    boolean valid;
    @nullable @utf8InCpp String errorMessage;
    @utf8InCpp String[] registeredPoints;
}
