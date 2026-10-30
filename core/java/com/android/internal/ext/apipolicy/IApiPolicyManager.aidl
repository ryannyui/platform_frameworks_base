package com.android.internal.ext.apipolicy;

import com.android.internal.ext.apipolicy.HookPointInfo;
import com.android.internal.ext.apipolicy.IApiPolicyListener;
import com.android.internal.ext.apipolicy.PolicyScriptInfo;
import com.android.internal.ext.apipolicy.PolicyScriptSummary;
import com.android.internal.ext.apipolicy.PolicyServiceStatus;
import com.android.internal.ext.apipolicy.ValidationResult;

/**
 * System service interface for managing runtime API policy scripts.
 *
 * @hide
 */
interface IApiPolicyManager {
    const int ERROR_PERSIST_FAILED = 1;

    List<HookPointInfo> listHookPoints();
    @nullable HookPointInfo getHookPoint(@utf8InCpp String pointId);

    List<PolicyScriptSummary> listScripts();
    @nullable PolicyScriptInfo getScript(@utf8InCpp String scriptId);
    PolicyServiceStatus getServiceStatus();
    void registerListener(IApiPolicyListener listener);
    void unregisterListener(IApiPolicyListener listener);

    ValidationResult validateScript(@utf8InCpp String source);
    ValidationResult upsertScript(@utf8InCpp String scriptId, @utf8InCpp String source, boolean enabled);
    boolean setScriptEnabled(@utf8InCpp String scriptId, boolean enabled);
    boolean reloadScript(@utf8InCpp String scriptId);
    boolean removeScript(@utf8InCpp String scriptId);

    List<String> getLogs(@nullable @utf8InCpp String scriptId, int maxEntries);
    void clearLogs(@nullable @utf8InCpp String scriptId);
}
