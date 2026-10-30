package com.android.server.ext.apipolicy;

import android.annotation.Nullable;
import android.util.ArrayMap;

/**
 * In-process {@code system_server} interface registered in {@link com.android.server.LocalServices}
 * for zero-IPC API policy evaluation at hook points.
 */
public interface ApiPolicyInternal {

    String ACTION_ALLOW = "allow";
    String ACTION_DROP = "drop";
    String ACTION_MODIFY = "modify";

    /**
     * Registers a system hook point definition so it appears in {@code listHookPoints()} and CLI.
     */
    void registerHookPoint(String pointId, String category, String description);

    /**
     * Lock-free fast-path check returning {@code true} only if the subsystem is enabled and at
     * least one active script has subscribed to {@code pointId} via {@code policy.on(...)}.
     */
    boolean isPointActive(String pointId);

    /**
     * Evaluates active script handlers bound to {@code pointId} in real time.
     *
     * @param pointId     target hook point identifier
     * @param inputFlatKv alternating key-value context array
     * @return decision map returned by Lua (e.g. {@code action = "modify"|"drop"|"allow"}),
     *         or {@code null} to allow original behavior unchanged
     */
    @Nullable
    ArrayMap<String, Object> evaluate(String pointId, @Nullable Object[] inputFlatKv);

    /**
     * Records a post-evaluation validation error (e.g. incomplete synthesized object) into the
     * policy service's diagnostic logs and counters.
     */
    void recordHookError(String pointId, @Nullable String scriptId, String errorMessage);

    /**
     * Registers a callback invoked asynchronously on {@link com.android.server.FgThread} whenever
     * active script bindings change (script applied, enabled, disabled, reloaded, or removed).
     */
    void registerBindingChangeListener(Runnable listener);
}
