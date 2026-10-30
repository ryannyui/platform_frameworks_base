package com.android.server.ext.apipolicy;

import android.Manifest;
import android.annotation.Nullable;
import android.content.Context;
import android.os.Binder;
import android.os.Build;
import android.os.Process;
import android.os.RemoteCallbackList;
import android.os.ResultReceiver;
import android.os.ServiceSpecificException;
import android.os.ShellCallback;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.util.ArrayMap;
import android.util.Slog;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.ext.apipolicy.HookPointInfo;
import com.android.internal.ext.apipolicy.IApiPolicyListener;
import com.android.internal.ext.apipolicy.IApiPolicyManager;
import com.android.internal.ext.apipolicy.PolicyScriptInfo;
import com.android.internal.ext.apipolicy.PolicyScriptSummary;
import com.android.internal.ext.apipolicy.PolicyServiceStatus;
import com.android.internal.ext.apipolicy.ValidationResult;
import com.android.internal.os.BackgroundThread;
import com.android.internal.util.DumpUtils;
import com.android.server.FgThread;
import com.android.server.SystemService;
import com.android.server.SystemServiceManager;
import com.android.server.utils.TimingsTraceAndSlog;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * System service managing runtime Lua 5.4 API policy scripts and dispatching hook points inside
 * {@code system_server}.
 */
public final class ApiPolicyManagerService extends SystemService {

    public static final String SERVICE_NAME = "apipolicy";
    public static final String PROP_DISABLE = "persist.sys.apipolicy.disable";
    static final int MAX_SCRIPT_SOURCE_BYTES = 512 * 1024;

    private static final String TAG = "ApiPolicyService";
    private static final long DEFAULT_MAX_MEM_BYTES = 2L * 1024 * 1024;
    private static final int DEFAULT_MAX_INIT_STEPS = 50_000;
    private static final int DEFAULT_MAX_EVAL_STEPS = 20_000;
    private static final int MAX_LOG_BUFFER_SIZE = 300;

    private static final CompiledScript[] EMPTY_BINDINGS = new CompiledScript[0];

    private static final class HookPointRecord {
        final String pointId;
        volatile boolean builtin;
        volatile String category;
        volatile String description;
        volatile CompiledScript[] activeBindings = EMPTY_BINDINGS;

        final AtomicLong invokeCount = new AtomicLong(0);
        final AtomicLong modifyCount = new AtomicLong(0);
        final AtomicLong dropCount = new AtomicLong(0);
        final AtomicLong errorCount = new AtomicLong(0);

        HookPointRecord(String pointId, boolean builtin, String category, String description) {
            this.pointId = pointId;
            this.builtin = builtin;
            this.category = category;
            this.description = description;
        }
    }

    private static final class ManagedScriptRecord {
        final String scriptId;
        String source;
        boolean enabled;
        long updatedAtMs;
        @Nullable CompiledScript compiled;
        @Nullable String lastCompileError;

        ManagedScriptRecord(String scriptId, String source, boolean enabled, long updatedAtMs) {
            this.scriptId = scriptId;
            this.source = source;
            this.enabled = enabled;
            this.updatedAtMs = updatedAtMs;
        }
    }

    private static final class LogEntry {
        final long timestampMs;
        final String scriptId;
        final String message;

        LogEntry(long timestampMs, String scriptId, String message) {
            this.timestampMs = timestampMs;
            this.scriptId = scriptId;
            this.message = message;
        }
    }

    private final Context mContext;
    private final PolicyScriptStore mStore;
    private final Object mConfigLock = new Object();
    private final Object mLogLock = new Object();

    @GuardedBy("mConfigLock")
    private final LinkedHashMap<String, ManagedScriptRecord> mScripts = new LinkedHashMap<>();

    @GuardedBy("mConfigLock")
    @Nullable
    private String mStorageError;

    @GuardedBy("mConfigLock")
    private int mRejectedScriptCount;

    @GuardedBy("mConfigLock")
    private long mConfigVersion;

    @GuardedBy("mConfigLock")
    private boolean mLastGloballyDisabled = isGloballyDisabled();

    @GuardedBy("mConfigLock")
    private long mGlobalStateSequence;

    private final ConcurrentHashMap<String, HookPointRecord> mHookPoints =
            new ConcurrentHashMap<>();

    private final CopyOnWriteArrayList<Runnable> mBindingChangeListeners =
            new CopyOnWriteArrayList<>();
    private final RemoteCallbackList<IApiPolicyListener> mPolicyListeners =
            new RemoteCallbackList<>();

    @GuardedBy("mLogLock")
    private final ArrayDeque<LogEntry> mLogs = new ArrayDeque<>(MAX_LOG_BUFFER_SIZE);

    private final LocalService mLocalService = new LocalService();
    private final BinderService mBinderService = new BinderService();

    public ApiPolicyManagerService(Context context) {
        this(context, new PolicyScriptStore());
    }

    ApiPolicyManagerService(Context context, PolicyScriptStore store) {
        super(context);
        mContext = context;
        mStore = store;
    }

    /**
     * Starts the service from {@code SystemServer#startOtherServices}. Failures are reported via
     * {@link Slog#wtf} and never abort system_server startup.
     */
    public static void start(Context context, SystemServiceManager ssm, TimingsTraceAndSlog t) {
        t.traceBegin("StartApiPolicyManagerService");
        try {
            ssm.startService(new ApiPolicyManagerService(context));
        } catch (Throwable e) {
            Slog.wtf(TAG, "Failed to start ApiPolicyManagerService", e);
        }
        t.traceEnd();
    }

    @Override
    public void onStart() {
        LocationPolicyHooks.registerHookPoints(mLocalService);
        loadPersistedScripts();
        SystemProperties.addChangeCallback(this::onSystemPropertiesChanged);
        publishLocalService(ApiPolicyInternal.class, mLocalService);
        publishBinderService(SERVICE_NAME, mBinderService);
        Slog.i(TAG, "ApiPolicyManagerService started (disabled=" + isGloballyDisabled() + ")");
    }

    static boolean isGloballyDisabled() {
        return SystemProperties.getBoolean(PROP_DISABLE, false);
    }

    private void onSystemPropertiesChanged() {
        boolean disabled = isGloballyDisabled();
        final long sequence;
        synchronized (mConfigLock) {
            if (disabled == mLastGloballyDisabled) {
                return;
            }
            mLastGloballyDisabled = disabled;
            sequence = ++mGlobalStateSequence;
            if (disabled) {
                bumpConfigVersionLocked();
            }
        }
        if (!disabled) {
            BackgroundThread.getHandler().post(() -> restoreScriptsAfterGlobalEnable(sequence));
        }
    }

    private void restoreScriptsAfterGlobalEnable(long expectedSequence) {
        synchronized (mConfigLock) {
            if (!isCurrentGlobalEnable(expectedSequence)) {
                return;
            }
            restoreEnabledScripts();
            if (!isCurrentGlobalEnable(expectedSequence)) {
                return;
            }
            bumpConfigVersionLocked();
        }
    }

    @GuardedBy("mConfigLock")
    private boolean isCurrentGlobalEnable(long expectedSequence) {
        return expectedSequence == mGlobalStateSequence
                && !mLastGloballyDisabled
                && !isGloballyDisabled();
    }

    void restoreEnabledScripts() {
        synchronized (mConfigLock) {
            for (ManagedScriptRecord rec : mScripts.values()) {
                if (rec.enabled && rec.compiled == null) {
                    compileIntoRecordLocked(rec);
                }
            }
            rebuildBindingsLocked();
        }
    }

    private void loadPersistedScripts() {
        loadPersistedScripts(isGloballyDisabled());
    }

    void loadPersistedScripts(boolean disabledByProp) {
        PolicyScriptStore.LoadResult persisted = mStore.loadAll();
        synchronized (mConfigLock) {
            mStorageError = persisted.errorMessage;
            mRejectedScriptCount = persisted.rejectedCount;
            for (PolicyScriptStore.PersistedScript item : persisted.scripts) {
                if (mScripts.containsKey(item.scriptId)) {
                    mRejectedScriptCount++;
                    continue;
                }
                ManagedScriptRecord rec = new ManagedScriptRecord(
                        item.scriptId, item.source, item.enabled, item.updatedAtMs);
                if (item.enabled && !disabledByProp) {
                    ValidationResult result = compileIntoRecordLocked(rec);
                    if (!result.valid) {
                        mRejectedScriptCount++;
                    }
                }
                mScripts.put(rec.scriptId, rec);
            }
            rebuildBindingsLocked();
            mConfigVersion = 1;
        }
    }

    @GuardedBy("mConfigLock")
    private ValidationResult compileIntoRecordLocked(ManagedScriptRecord rec) {
        ArrayList<String> registeredPoints = new ArrayList<>();
        ArrayList<String> initLogs = new ArrayList<>();
        String[] errorOut = new String[1];

        long handle = PolicyScriptEngine.nativeCompileScript(
                rec.scriptId,
                rec.source,
                DEFAULT_MAX_MEM_BYTES,
                DEFAULT_MAX_INIT_STEPS,
                registeredPoints,
                initLogs,
                errorOut);

        if (!initLogs.isEmpty()) {
            appendLogs(rec.scriptId, initLogs);
        }

        ValidationResult vr = new ValidationResult();
        if (handle == 0) {
            String errMsg = (errorOut[0] != null) ? errorOut[0] : "Compilation failed";
            rec.lastCompileError = errMsg;
            vr.valid = false;
            vr.errorMessage = errMsg;
            vr.registeredPoints = new String[0];
            appendSingleLog(rec.scriptId, "[compile-error] " + errMsg);
            return vr;
        }

        for (String pt : registeredPoints) {
            mHookPoints.computeIfAbsent(
                    pt, id -> new HookPointRecord(id, false, "custom", "Dynamic"));
        }

        CompiledScript nextCompiled =
                new CompiledScript(rec.scriptId, handle, registeredPoints);
        CompiledScript prevCompiled = rec.compiled;
        rec.compiled = nextCompiled;
        rec.lastCompileError = null;

        if (prevCompiled != null) {
            prevCompiled.releaseOwner();
        }

        vr.valid = true;
        vr.errorMessage = null;
        vr.registeredPoints = registeredPoints.toArray(new String[0]);
        return vr;
    }

    @GuardedBy("mConfigLock")
    private void rebuildBindingsLocked() {
        ArrayMap<String, ArrayList<CompiledScript>> perPoint = new ArrayMap<>();
        for (ManagedScriptRecord rec : mScripts.values()) {
            if (!rec.enabled || rec.compiled == null) {
                continue;
            }
            for (String pt : rec.compiled.registeredPoints) {
                ArrayList<CompiledScript> list = perPoint.get(pt);
                if (list == null) {
                    list = new ArrayList<>(2);
                    perPoint.put(pt, list);
                }
                list.add(rec.compiled);
            }
        }

        for (Map.Entry<String, HookPointRecord> e : mHookPoints.entrySet()) {
            HookPointRecord rec = e.getValue();
            ArrayList<CompiledScript> bound = perPoint.get(e.getKey());
            if (bound == null || bound.isEmpty()) {
                rec.activeBindings = EMPTY_BINDINGS;
                if (!rec.builtin) {
                    mHookPoints.remove(e.getKey(), rec);
                }
            } else {
                rec.activeBindings = bound.toArray(new CompiledScript[0]);
            }
        }
        dispatchBindingChangeAsync();
    }

    @GuardedBy("mConfigLock")
    private void bumpConfigVersionLocked() {
        mConfigVersion++;
        dispatchPolicyChangeAsync();
    }

    private void dispatchPolicyChangeAsync() {
        final long version;
        synchronized (mConfigLock) {
            version = mConfigVersion;
        }
        if (mPolicyListeners.getRegisteredCallbackCount() == 0) {
            return;
        }
        FgThread.getHandler().post(() -> {
            int count = mPolicyListeners.beginBroadcast();
            try {
                for (int i = 0; i < count; i++) {
                    try {
                        mPolicyListeners.getBroadcastItem(i).onPolicyChanged(version);
                    } catch (Throwable t) {
                        Slog.e(TAG, "Policy listener failed", t);
                    }
                }
            } finally {
                mPolicyListeners.finishBroadcast();
            }
        });
    }

    private void dispatchBindingChangeAsync() {
        if (mBindingChangeListeners.isEmpty()) {
            return;
        }
        FgThread.getHandler().post(() -> {
            for (Runnable listener : mBindingChangeListeners) {
                try {
                    listener.run();
                } catch (Throwable t) {
                    Slog.e(TAG, "Binding change listener failed", t);
                }
            }
        });
    }

    @GuardedBy("mConfigLock")
    private LinkedHashMap<String, ManagedScriptRecord> copyScriptsLocked() {
        LinkedHashMap<String, ManagedScriptRecord> copy = new LinkedHashMap<>();
        for (ManagedScriptRecord rec : mScripts.values()) {
            ManagedScriptRecord item = new ManagedScriptRecord(
                    rec.scriptId, rec.source, rec.enabled, rec.updatedAtMs);
            item.compiled = rec.compiled;
            item.lastCompileError = rec.lastCompileError;
            copy.put(item.scriptId, item);
        }
        return copy;
    }

    private static IdentityHashMap<CompiledScript, Boolean> collectCompiled(
            Iterable<ManagedScriptRecord> records) {
        IdentityHashMap<CompiledScript, Boolean> compiled = new IdentityHashMap<>();
        for (ManagedScriptRecord rec : records) {
            if (rec.compiled != null) {
                compiled.put(rec.compiled, Boolean.TRUE);
            }
        }
        return compiled;
    }

    @GuardedBy("mConfigLock")
    private void discardCandidateScriptsLocked(
            LinkedHashMap<String, ManagedScriptRecord> candidate) {
        IdentityHashMap<CompiledScript, Boolean> current = collectCompiled(mScripts.values());
        for (ManagedScriptRecord rec : candidate.values()) {
            if (rec.compiled != null && !current.containsKey(rec.compiled)) {
                rec.compiled.releaseOwner();
                rec.compiled = null;
            }
        }
        mHookPoints.values().removeIf(
                rec -> !rec.builtin && rec.activeBindings.length == 0);
    }

    @GuardedBy("mConfigLock")
    private void commitCandidateScriptsLocked(
            LinkedHashMap<String, ManagedScriptRecord> candidate) {
        IdentityHashMap<CompiledScript, Boolean> retained = collectCompiled(candidate.values());
        LinkedHashMap<String, ManagedScriptRecord> previous =
                new LinkedHashMap<>(mScripts);
        mScripts.clear();
        mScripts.putAll(candidate);
        rebuildBindingsLocked();
        for (ManagedScriptRecord rec : previous.values()) {
            if (rec.compiled != null && !retained.containsKey(rec.compiled)) {
                rec.compiled.releaseOwner();
                rec.compiled = null;
            }
        }
        bumpConfigVersionLocked();
    }

    @GuardedBy("mConfigLock")
    private void persistCandidateScriptsLocked(
            LinkedHashMap<String, ManagedScriptRecord> candidate) {
        List<PolicyScriptStore.PersistedScript> snapshot = new ArrayList<>(candidate.size());
        for (ManagedScriptRecord rec : candidate.values()) {
            snapshot.add(new PolicyScriptStore.PersistedScript(
                    rec.scriptId, rec.source, rec.enabled, rec.updatedAtMs));
        }
        try {
            mStore.saveAll(snapshot);
        } catch (Exception e) {
            mStorageError = "Store write failed (" + e.getClass().getSimpleName() + ")";
            discardCandidateScriptsLocked(candidate);
            throw new ServiceSpecificException(IApiPolicyManager.ERROR_PERSIST_FAILED,
                    "Failed to persist policy scripts; active configuration was not changed");
        }
        mStorageError = null;
        commitCandidateScriptsLocked(candidate);
    }

    private void tripCircuitBreakerAsync(CompiledScript tripped) {
        synchronized (mConfigLock) {
            ManagedScriptRecord current = mScripts.get(tripped.scriptId);
            if (current == null || current.compiled != tripped || !current.enabled) {
                return;
            }
            LinkedHashMap<String, ManagedScriptRecord> candidate = copyScriptsLocked();
            ManagedScriptRecord rec = candidate.get(tripped.scriptId);
            rec.enabled = false;
            rec.lastCompileError =
                    "Auto-disabled after " + CompiledScript.CIRCUIT_BREAKER_THRESHOLD
                            + " consecutive errors: " + tripped.lastError;
            rec.compiled = null;
            try {
                persistCandidateScriptsLocked(candidate);
            } catch (ServiceSpecificException e) {
                current.enabled = false;
                current.lastCompileError = rec.lastCompileError;
                current.compiled = null;
                rebuildBindingsLocked();
                tripped.releaseOwner();
                bumpConfigVersionLocked();
                appendSingleLog(tripped.scriptId,
                        "[circuit-breaker] Auto-disabled in memory, but persistence failed");
                Slog.e(TAG, "Failed to persist circuit breaker for " + tripped.scriptId, e);
                return;
            }
        }
        appendSingleLog(tripped.scriptId,
                "[circuit-breaker] Auto-disabled script after repeated runtime errors");
        Slog.w(TAG, "Auto-disabled policy script " + tripped.scriptId + " due to repeated errors");
    }

    private void appendLogs(String scriptId, List<String> lines) {
        long now = System.currentTimeMillis();
        synchronized (mLogLock) {
            for (String line : lines) {
                if (mLogs.size() >= MAX_LOG_BUFFER_SIZE) {
                    mLogs.removeFirst();
                }
                mLogs.addLast(new LogEntry(now, scriptId, line));
            }
        }
    }

    private void appendSingleLog(String scriptId, String message) {
        long now = System.currentTimeMillis();
        synchronized (mLogLock) {
            if (mLogs.size() >= MAX_LOG_BUFFER_SIZE) {
                mLogs.removeFirst();
            }
            mLogs.addLast(new LogEntry(now, scriptId, message));
        }
    }

    private void enforceManagePermission() {
        int uid = Binder.getCallingUid();
        if (uid == Process.ROOT_UID || uid == Process.SYSTEM_UID) {
            return;
        }
        if (Build.IS_DEBUGGABLE && uid == Process.SHELL_UID) {
            return;
        }
        enforceSystemUser(uid);
        mContext.enforceCallingOrSelfPermission(
                Manifest.permission.MANAGE_API_POLICY, "Requires MANAGE_API_POLICY");
    }

    static void enforceSystemUser(int uid) {
        if (UserHandle.getUserId(uid) != UserHandle.USER_SYSTEM) {
            throw new SecurityException("API policy management requires the system user");
        }
    }

    // ---- Package-private management methods shared by BinderService & ApiPolicyShellCommand ----

    List<HookPointInfo> listHookPointsInternal() {
        List<HookPointInfo> out = new ArrayList<>(mHookPoints.size());
        for (HookPointRecord rec : mHookPoints.values()) {
            out.add(toHookPointInfo(rec));
        }
        out.sort(Comparator.comparing(info -> info.pointId));
        return out;
    }

    @Nullable
    HookPointInfo getHookPointInternal(String pointId) {
        if (pointId == null) {
            return null;
        }
        HookPointRecord rec = mHookPoints.get(pointId);
        return (rec != null) ? toHookPointInfo(rec) : null;
    }

    private static HookPointInfo toHookPointInfo(HookPointRecord rec) {
        HookPointInfo info = new HookPointInfo();
        info.pointId = rec.pointId;
        info.category = rec.category;
        info.description = rec.description;
        CompiledScript[] bindings = rec.activeBindings;
        String[] scriptIds = new String[bindings.length];
        for (int i = 0; i < bindings.length; i++) {
            scriptIds[i] = bindings[i].scriptId;
        }
        info.boundScriptIds = scriptIds;
        info.invokeCount = rec.invokeCount.get();
        info.modifyCount = rec.modifyCount.get();
        info.dropCount = rec.dropCount.get();
        info.errorCount = rec.errorCount.get();
        return info;
    }

    List<PolicyScriptSummary> listScriptsInternal() {
        synchronized (mConfigLock) {
            List<PolicyScriptSummary> out = new ArrayList<>(mScripts.size());
            for (ManagedScriptRecord rec : mScripts.values()) {
                out.add(toScriptSummaryLocked(rec));
            }
            return out;
        }
    }

    @Nullable
    PolicyScriptInfo getScriptInternal(String scriptId) {
        if (scriptId == null) {
            return null;
        }
        synchronized (mConfigLock) {
            ManagedScriptRecord rec = mScripts.get(scriptId);
            return (rec != null) ? toScriptInfoLocked(rec) : null;
        }
    }

    @GuardedBy("mConfigLock")
    private static PolicyScriptSummary toScriptSummaryLocked(ManagedScriptRecord rec) {
        PolicyScriptSummary info = new PolicyScriptSummary();
        info.scriptId = rec.scriptId;
        info.enabled = rec.enabled;
        info.updatedAtMs = rec.updatedAtMs;
        CompiledScript cs = rec.compiled;
        if (cs != null) {
            info.registeredPoints = cs.registeredPoints.toArray(new String[0]);
            info.invokeCount = cs.invokeCount.get();
            info.errorCount = cs.errorCount.get();
            info.lastEvalMicros = cs.lastEvalMicros.get();
            info.lastError = (cs.lastError != null) ? cs.lastError : rec.lastCompileError;
        } else {
            info.registeredPoints = new String[0];
            info.invokeCount = 0;
            info.errorCount = 0;
            info.lastEvalMicros = 0;
            info.lastError = rec.lastCompileError;
        }
        return info;
    }

    @GuardedBy("mConfigLock")
    private static PolicyScriptInfo toScriptInfoLocked(ManagedScriptRecord rec) {
        PolicyScriptSummary summary = toScriptSummaryLocked(rec);
        PolicyScriptInfo info = new PolicyScriptInfo();
        info.scriptId = summary.scriptId;
        info.enabled = summary.enabled;
        info.source = rec.source;
        info.registeredPoints = summary.registeredPoints;
        info.invokeCount = summary.invokeCount;
        info.errorCount = summary.errorCount;
        info.lastEvalMicros = summary.lastEvalMicros;
        info.lastError = summary.lastError;
        info.updatedAtMs = summary.updatedAtMs;
        return info;
    }

    @Nullable
    private static String checkSourceBounds(@Nullable String source) {
        if (source == null || source.isEmpty()) {
            return "Script source must not be empty";
        }
        if (source.length() > MAX_SCRIPT_SOURCE_BYTES
                || source.getBytes(StandardCharsets.UTF_8).length > MAX_SCRIPT_SOURCE_BYTES) {
            return "Script exceeds maximum size of " + MAX_SCRIPT_SOURCE_BYTES + " bytes";
        }
        return null;
    }

    ValidationResult validateScriptInternal(String source) {
        ValidationResult res = new ValidationResult();
        res.registeredPoints = new String[0];
        String boundsErr = checkSourceBounds(source);
        if (boundsErr != null) {
            res.valid = false;
            res.errorMessage = boundsErr;
            return res;
        }

        ArrayList<String> registeredPoints = new ArrayList<>();
        String[] errorOut = new String[1];
        long handle = PolicyScriptEngine.nativeCompileScript(
                "validate",
                source,
                DEFAULT_MAX_MEM_BYTES,
                DEFAULT_MAX_INIT_STEPS,
                registeredPoints,
                /* outInitLogs= */ null,
                errorOut);
        if (handle == 0) {
            res.valid = false;
            res.errorMessage = (errorOut[0] != null) ? errorOut[0] : "Validation failed";
            return res;
        }

        PolicyScriptEngine.nativeDestroyScript(handle);
        res.valid = true;
        res.errorMessage = null;
        res.registeredPoints = registeredPoints.toArray(new String[0]);
        return res;
    }

    ValidationResult upsertScriptInternal(String scriptId, String source, boolean enabled) {
        ValidationResult res = new ValidationResult();
        res.registeredPoints = new String[0];
        if (!isValidScriptId(scriptId)) {
            res.valid = false;
            res.errorMessage = "Invalid scriptId (allowed: [A-Za-z0-9_.-], 1..64 chars)";
            return res;
        }
        String boundsErr = checkSourceBounds(source);
        if (boundsErr != null) {
            res.valid = false;
            res.errorMessage = boundsErr;
            return res;
        }

        ValidationResult dryRunForDisabled = null;
        if (!enabled) {
            dryRunForDisabled = validateScriptInternal(source);
            if (!dryRunForDisabled.valid) {
                return dryRunForDisabled;
            }
        }

        long now = System.currentTimeMillis();
        synchronized (mConfigLock) {
            LinkedHashMap<String, ManagedScriptRecord> candidate = copyScriptsLocked();
            ManagedScriptRecord existing = candidate.get(scriptId);
            if (existing == null) {
                ManagedScriptRecord rec = new ManagedScriptRecord(scriptId, source, enabled, now);
                if (enabled) {
                    ValidationResult compRes = compileIntoRecordLocked(rec);
                    if (!compRes.valid) {
                        discardCandidateScriptsLocked(candidate);
                        return compRes;
                    }
                    res = compRes;
                } else {
                    res = dryRunForDisabled;
                }
                candidate.put(scriptId, rec);
            } else {
                existing.source = source;
                existing.enabled = enabled;
                existing.updatedAtMs = now;

                if (enabled) {
                    existing.compiled = null;
                    ValidationResult compRes = compileIntoRecordLocked(existing);
                    if (!compRes.valid) {
                        mScripts.get(scriptId).lastCompileError = existing.lastCompileError;
                        discardCandidateScriptsLocked(candidate);
                        return compRes;
                    }
                    res = compRes;
                } else {
                    existing.compiled = null;
                    existing.lastCompileError = null;
                    res = dryRunForDisabled;
                }
            }

            persistCandidateScriptsLocked(candidate);
            return res;
        }
    }

    boolean setScriptEnabledInternal(String scriptId, boolean enabled) {
        if (scriptId == null) {
            return false;
        }
        synchronized (mConfigLock) {
            ManagedScriptRecord current = mScripts.get(scriptId);
            if (current == null) {
                return false;
            }
            if (current.enabled == enabled && (!enabled || current.compiled != null)) {
                return true;
            }
            LinkedHashMap<String, ManagedScriptRecord> candidate = copyScriptsLocked();
            ManagedScriptRecord rec = candidate.get(scriptId);
            if (enabled) {
                rec.compiled = null;
                ValidationResult vr = compileIntoRecordLocked(rec);
                if (!vr.valid) {
                    current.lastCompileError = rec.lastCompileError;
                    discardCandidateScriptsLocked(candidate);
                    return false;
                }
                rec.enabled = true;
            } else {
                rec.enabled = false;
                rec.compiled = null;
            }
            rec.updatedAtMs = System.currentTimeMillis();
            persistCandidateScriptsLocked(candidate);
            return true;
        }
    }

    boolean reloadScriptInternal(String scriptId) {
        if (scriptId == null) {
            return false;
        }
        synchronized (mConfigLock) {
            ManagedScriptRecord rec = mScripts.get(scriptId);
            if (rec == null || !rec.enabled) {
                return false;
            }
            ManagedScriptRecord candidate = new ManagedScriptRecord(
                    rec.scriptId, rec.source, rec.enabled, rec.updatedAtMs);
            ValidationResult vr = compileIntoRecordLocked(candidate);
            if (!vr.valid) {
                rec.lastCompileError = candidate.lastCompileError;
                return false;
            }
            CompiledScript previous = rec.compiled;
            rec.compiled = candidate.compiled;
            rec.lastCompileError = null;
            rebuildBindingsLocked();
            if (previous != null) {
                previous.releaseOwner();
            }
            bumpConfigVersionLocked();
            return true;
        }
    }

    boolean removeScriptInternal(String scriptId) {
        if (scriptId == null) {
            return false;
        }
        synchronized (mConfigLock) {
            if (!mScripts.containsKey(scriptId)) {
                return false;
            }
            LinkedHashMap<String, ManagedScriptRecord> candidate = copyScriptsLocked();
            candidate.remove(scriptId);
            persistCandidateScriptsLocked(candidate);
            return true;
        }
    }

    PolicyServiceStatus getServiceStatusInternal() {
        synchronized (mConfigLock) {
            PolicyServiceStatus status = new PolicyServiceStatus();
            status.globallyDisabled = isGloballyDisabled();
            status.storageHealthy = mStorageError == null;
            status.storageError = mStorageError;
            status.loadedScriptCount = mScripts.size();
            status.rejectedScriptCount = mRejectedScriptCount;
            status.configVersion = mConfigVersion;
            return status;
        }
    }

    void registerListenerInternal(@Nullable IApiPolicyListener listener) {
        if (listener != null) {
            mPolicyListeners.register(listener);
        }
    }

    void unregisterListenerInternal(@Nullable IApiPolicyListener listener) {
        if (listener != null) {
            mPolicyListeners.unregister(listener);
        }
    }

    List<String> getLogsInternal(@Nullable String scriptId, int maxEntries) {
        int limit = (maxEntries <= 0) ? 100 : Math.min(maxEntries, MAX_LOG_BUFFER_SIZE);
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
        List<String> matched = new ArrayList<>();
        synchronized (mLogLock) {
            for (LogEntry entry : mLogs) {
                if (scriptId == null || scriptId.isEmpty() || scriptId.equals(entry.scriptId)) {
                    matched.add(sdf.format(new Date(entry.timestampMs))
                            + " [" + entry.scriptId + "] " + entry.message);
                }
            }
        }
        if (matched.size() <= limit) {
            return matched;
        }
        return new ArrayList<>(matched.subList(matched.size() - limit, matched.size()));
    }

    void clearLogsInternal(@Nullable String scriptId) {
        synchronized (mLogLock) {
            if (scriptId == null || scriptId.isEmpty()) {
                mLogs.clear();
            } else {
                mLogs.removeIf(entry -> scriptId.equals(entry.scriptId));
            }
        }
    }

    private static boolean isValidScriptId(@Nullable String id) {
        if (id == null || id.isEmpty() || id.length() > 64) {
            return false;
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '_' || c == '-' || c == '.';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private final class LocalService implements ApiPolicyInternal {

        @Override
        public void registerHookPoint(String pointId, String category, String description) {
            HookPointRecord existing = mHookPoints.get(pointId);
            if (existing != null) {
                existing.builtin = true;
                existing.category = category;
                existing.description = description;
            } else {
                mHookPoints.put(
                        pointId, new HookPointRecord(pointId, true, category, description));
            }
        }

        @Override
        public boolean isPointActive(String pointId) {
            try {
                if (pointId == null || isGloballyDisabled()) {
                    return false;
                }
                HookPointRecord rec = mHookPoints.get(pointId);
                return rec != null && rec.activeBindings.length > 0;
            } catch (Throwable t) {
                Slog.e(TAG, "isPointActive failed for " + pointId, t);
                return false;
            }
        }

        @Override
        @Nullable
        public ArrayMap<String, Object> evaluate(String pointId, @Nullable Object[] inputFlatKv) {
            try {
                if (pointId == null || isGloballyDisabled()) {
                    return null;
                }
                HookPointRecord pointRec = mHookPoints.get(pointId);
                if (pointRec == null) {
                    return null;
                }
                CompiledScript[] bindings = pointRec.activeBindings;
                if (bindings.length == 0) {
                    return null;
                }

                pointRec.invokeCount.incrementAndGet();

                Object[] enrichedKv = injectPointId(pointId, inputFlatKv);

                for (CompiledScript script : bindings) {
                    CompiledScript.EvalOutcome outcome =
                            script.invoke(pointId, enrichedKv, DEFAULT_MAX_EVAL_STEPS);
                    if (outcome == null) {
                        continue;
                    }
                    if (!outcome.logs.isEmpty()) {
                        appendLogs(script.scriptId, outcome.logs);
                    }
                    if (outcome.error != null) {
                        pointRec.errorCount.incrementAndGet();
                        appendSingleLog(script.scriptId,
                                "[" + pointId + " error] " + outcome.error);
                        if (outcome.tripCircuitBreaker) {
                            BackgroundThread.getHandler().post(
                                    () -> tripCircuitBreakerAsync(script));
                        }
                        continue;
                    }
                    if (outcome.decision == null) {
                        continue;
                    }
                    Object actionObj = outcome.decision.get("action");
                    String action = (actionObj instanceof String s) ? s : ACTION_ALLOW;
                    if (ACTION_DROP.equals(action)) {
                        pointRec.dropCount.incrementAndGet();
                        return outcome.decision;
                    }
                    if (ACTION_MODIFY.equals(action)) {
                        pointRec.modifyCount.incrementAndGet();
                        return outcome.decision;
                    }
                }
                return null;
            } catch (Throwable t) {
                Slog.e(TAG, "evaluate failed for " + pointId, t);
                return null;
            }
        }

        @Override
        public void recordHookError(
                String pointId, @Nullable String scriptId, String errorMessage) {
            try {
                HookPointRecord rec = mHookPoints.get(pointId);
                if (rec != null) {
                    rec.errorCount.incrementAndGet();
                }
                String tag = (scriptId != null && !scriptId.isEmpty()) ? scriptId : pointId;
                appendSingleLog(tag, "[" + pointId + " validation] " + errorMessage);
            } catch (Throwable t) {
                Slog.e(TAG, "recordHookError failed for " + pointId, t);
            }
        }

        @Override
        public void registerBindingChangeListener(Runnable listener) {
            if (listener != null) {
                mBindingChangeListeners.addIfAbsent(listener);
            }
        }

        private static Object[] injectPointId(String pointId, @Nullable Object[] inputFlatKv) {
            if (inputFlatKv == null || inputFlatKv.length == 0) {
                return new Object[] {"point_id", pointId};
            }
            Object[] copy = new Object[inputFlatKv.length + 2];
            copy[0] = "point_id";
            copy[1] = pointId;
            System.arraycopy(inputFlatKv, 0, copy, 2, inputFlatKv.length);
            return copy;
        }
    }

    private final class BinderService extends IApiPolicyManager.Stub {

        @Override
        public List<HookPointInfo> listHookPoints() {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return listHookPointsInternal();
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        @Nullable
        public HookPointInfo getHookPoint(String pointId) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return getHookPointInternal(pointId);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public List<PolicyScriptSummary> listScripts() {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return listScriptsInternal();
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        @Nullable
        public PolicyScriptInfo getScript(String scriptId) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return getScriptInternal(scriptId);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public PolicyServiceStatus getServiceStatus() {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return getServiceStatusInternal();
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public void registerListener(IApiPolicyListener listener) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                registerListenerInternal(listener);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public void unregisterListener(IApiPolicyListener listener) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                unregisterListenerInternal(listener);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public ValidationResult validateScript(String source) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return validateScriptInternal(source);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public ValidationResult upsertScript(String scriptId, String source, boolean enabled) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return upsertScriptInternal(scriptId, source, enabled);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public boolean setScriptEnabled(String scriptId, boolean enabled) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return setScriptEnabledInternal(scriptId, enabled);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public boolean reloadScript(String scriptId) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return reloadScriptInternal(scriptId);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public boolean removeScript(String scriptId) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return removeScriptInternal(scriptId);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public List<String> getLogs(@Nullable String scriptId, int maxEntries) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                return getLogsInternal(scriptId, maxEntries);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public void clearLogs(@Nullable String scriptId) {
            enforceManagePermission();
            final long token = Binder.clearCallingIdentity();
            try {
                clearLogsInternal(scriptId);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        @Override
        public void onShellCommand(
                FileDescriptor in,
                FileDescriptor out,
                FileDescriptor err,
                String[] args,
                ShellCallback callback,
                ResultReceiver resultReceiver) {
            new ApiPolicyShellCommand(ApiPolicyManagerService.this)
                    .exec(this, in, out, err, args, callback, resultReceiver);
        }

        @Override
        protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
            if (!DumpUtils.checkDumpPermission(mContext, TAG, pw)) {
                return;
            }
            pw.println("ApiPolicyManagerService status:");
            PolicyServiceStatus status = getServiceStatusInternal();
            pw.println("  Globally disabled (" + PROP_DISABLE + "): "
                    + status.globallyDisabled);
            pw.println("  Storage healthy: " + status.storageHealthy);
            if (status.storageError != null) {
                pw.println("  Storage error: " + status.storageError);
            }
            pw.println("  Loaded scripts: " + status.loadedScriptCount);
            pw.println("  Rejected during restore: " + status.rejectedScriptCount);
            pw.println("  Config version: " + status.configVersion);
            pw.println();
            pw.println("Registered Hook Points:");
            for (HookPointInfo hp : listHookPointsInternal()) {
                pw.printf(Locale.US,
                        "  - %s [%s] bound=%s invoke=%d modify=%d drop=%d error=%d%n",
                        hp.pointId, hp.category, String.join(",", hp.boundScriptIds),
                        hp.invokeCount, hp.modifyCount, hp.dropCount, hp.errorCount);
            }
            pw.println();
            pw.println("Scripts:");
            for (PolicyScriptSummary sc : listScriptsInternal()) {
                pw.printf(Locale.US,
                        "  - %s enabled=%b points=[%s] invoke=%d error=%d lastEvalUs=%d"
                                + " updatedAtMs=%d%n",
                        sc.scriptId, sc.enabled, String.join(",", sc.registeredPoints),
                        sc.invokeCount, sc.errorCount, sc.lastEvalMicros, sc.updatedAtMs);
                if (sc.lastError != null) {
                    pw.println("      lastError: " + sc.lastError);
                }
            }
            pw.println();
            pw.println("Recent Logs:");
            List<String> logs = getLogsInternal(null, 50);
            if (logs.isEmpty()) {
                pw.println("  (empty)");
            } else {
                for (String line : logs) {
                    pw.println("  " + line);
                }
            }
        }
    }
}
