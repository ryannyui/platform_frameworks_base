package com.android.internal.ext.apipolicy;

/**
 * Receives asynchronous API policy configuration and health state changes.
 *
 * @hide
 */
oneway interface IApiPolicyListener {
    void onPolicyChanged(long configVersion);
}
