package com.android.server.ext.apipolicy;

import android.os.Binder;
import android.os.Build;
import android.os.Process;
import android.os.ShellCommand;

import com.android.internal.ext.apipolicy.HookPointInfo;
import com.android.internal.ext.apipolicy.PolicyScriptInfo;
import com.android.internal.ext.apipolicy.ValidationResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * {@code adb shell cmd apipolicy} developer CLI for managing and testing runtime Lua policy
 * scripts.
 */
final class ApiPolicyShellCommand extends ShellCommand {

    private final ApiPolicyManagerService mService;

    ApiPolicyShellCommand(ApiPolicyManagerService service) {
        mService = service;
    }

    @Override
    public int onCommand(String cmd) {
        final int callingUid = Binder.getCallingUid();
        if (callingUid != Process.ROOT_UID
                && !(Build.IS_DEBUGGABLE && callingUid == Process.SHELL_UID)) {
            getErrPrintWriter().println("Error: cmd apipolicy is restricted to root/debug shell");
            return -1;
        }

        if (cmd == null) {
            return handleDefaultCommands(null);
        }

        PrintWriter pw = getOutPrintWriter();
        PrintWriter err = getErrPrintWriter();

        try {
            return switch (cmd) {
                case "points" -> runPoints(pw);
                case "scripts" -> runScripts(pw);
                case "show" -> runShow(pw, err);
                case "validate" -> runValidate(pw, err);
                case "apply" -> runApply(pw, err);
                case "enable" -> runSetEnabled(pw, err, true);
                case "disable" -> runSetEnabled(pw, err, false);
                case "reload" -> runReload(pw, err);
                case "remove" -> runRemove(pw, err);
                case "logs" -> runLogs(pw);
                case "clear-logs" -> runClearLogs(pw);
                default -> handleDefaultCommands(cmd);
            };
        } catch (Exception e) {
            err.println("Error: " + e.getMessage());
            return -1;
        }
    }

    private int runPoints(PrintWriter pw) {
        List<HookPointInfo> points = mService.listHookPointsInternal();
        if (points.isEmpty()) {
            pw.println("No hook points registered.");
            return 0;
        }
        for (HookPointInfo p : points) {
            pw.printf(Locale.US,
                    "%s [%s]%n  bound=[%s] invoke=%d modify=%d drop=%d error=%d%n  desc: %s%n",
                    p.pointId,
                    p.category,
                    String.join(", ", p.boundScriptIds),
                    p.invokeCount,
                    p.modifyCount,
                    p.dropCount,
                    p.errorCount,
                    p.description);
        }
        return 0;
    }

    private int runScripts(PrintWriter pw) {
        List<PolicyScriptInfo> scripts = mService.listScriptsInternal();
        if (scripts.isEmpty()) {
            pw.println("No scripts configured.");
            return 0;
        }
        for (PolicyScriptInfo s : scripts) {
            pw.printf(Locale.US,
                    "%s  enabled=%b  points=[%s]  invoke=%d  error=%d  lastEvalUs=%d"
                            + "  updatedAtMs=%d%n",
                    s.scriptId,
                    s.enabled,
                    String.join(", ", s.registeredPoints),
                    s.invokeCount,
                    s.errorCount,
                    s.lastEvalMicros,
                    s.updatedAtMs);
            if (s.lastError != null) {
                pw.println("  lastError: " + s.lastError);
            }
        }
        return 0;
    }

    private int runShow(PrintWriter pw, PrintWriter err) {
        String id = getNextArgRequired();
        PolicyScriptInfo info = mService.getScriptInternal(id);
        if (info == null) {
            err.println("Script not found: " + id);
            return 1;
        }
        pw.println("-- scriptId: " + info.scriptId + " (enabled=" + info.enabled + ")");
        pw.println(info.source);
        return 0;
    }

    private int runValidate(PrintWriter pw, PrintWriter err) throws IOException {
        String srcSpec = getNextArgRequired();
        String source = readScriptSource(srcSpec, err);
        if (source == null) {
            return 1;
        }
        ValidationResult res = mService.validateScriptInternal(source);
        if (res.valid) {
            pw.printf(Locale.US,
                    "OK: valid (registeredPoints=[%s])%n",
                    String.join(", ", res.registeredPoints));
            return 0;
        }
        err.println("INVALID: " + res.errorMessage);
        return 1;
    }

    private int runApply(PrintWriter pw, PrintWriter err) throws IOException {
        boolean enabled = true;
        String arg = getNextArgRequired();
        if ("--disabled".equals(arg)) {
            enabled = false;
            arg = getNextArgRequired();
        }
        String scriptId = arg;
        String srcSpec = getNextArgRequired();

        String source = readScriptSource(srcSpec, err);
        if (source == null) {
            return 1;
        }

        ValidationResult res = mService.upsertScriptInternal(scriptId, source, enabled);
        if (!res.valid) {
            err.println("Failed to apply script '" + scriptId + "': " + res.errorMessage);
            return 1;
        }
        pw.printf(Locale.US,
                "Applied script '%s' (enabled=%b, registeredPoints=[%s])%n",
                scriptId, enabled, String.join(", ", res.registeredPoints));
        return 0;
    }

    private int runSetEnabled(PrintWriter pw, PrintWriter err, boolean enabled) {
        String scriptId = getNextArgRequired();
        if (!mService.setScriptEnabledInternal(scriptId, enabled)) {
            PolicyScriptInfo info = mService.getScriptInternal(scriptId);
            if (info == null) {
                err.println("Script not found: " + scriptId);
            } else {
                err.println("Failed to update script '" + scriptId + "': " + info.lastError);
            }
            return 1;
        }
        pw.println((enabled ? "Enabled " : "Disabled ") + scriptId);
        return 0;
    }

    private int runReload(PrintWriter pw, PrintWriter err) {
        String scriptId = getNextArgRequired();
        if (!mService.reloadScriptInternal(scriptId)) {
            PolicyScriptInfo info = mService.getScriptInternal(scriptId);
            if (info == null) {
                err.println("Script not found: " + scriptId);
            } else if (!info.enabled) {
                err.println("Script '" + scriptId + "' is disabled; enable it before reloading");
            } else {
                err.println("Failed to reload script '" + scriptId + "': " + info.lastError);
            }
            return 1;
        }
        pw.println("Reloaded " + scriptId);
        return 0;
    }

    private int runRemove(PrintWriter pw, PrintWriter err) {
        String scriptId = getNextArgRequired();
        if (!mService.removeScriptInternal(scriptId)) {
            err.println("Script not found: " + scriptId);
            return 1;
        }
        pw.println("Removed " + scriptId);
        return 0;
    }

    private int runLogs(PrintWriter pw) {
        String first = getNextArg();
        String scriptId = null;
        int limit = 100;
        if (first != null) {
            String second = getNextArg();
            if (second != null) {
                scriptId = "-".equals(first) ? null : first;
                limit = Integer.parseInt(second);
            } else if (!"-".equals(first)) {
                try {
                    limit = Integer.parseInt(first);
                } catch (NumberFormatException ignored) {
                    scriptId = first;
                }
            }
        }
        List<String> logs = mService.getLogsInternal(scriptId, limit);
        for (String line : logs) {
            pw.println(line);
        }
        return 0;
    }

    private int runClearLogs(PrintWriter pw) {
        String scriptId = getNextArg();
        mService.clearLogsInternal("-".equals(scriptId) ? null : scriptId);
        pw.println("Logs cleared.");
        return 0;
    }

    private String readScriptSource(String srcSpec, PrintWriter err) throws IOException {
        if ("-".equals(srcSpec)) {
            return readAllUtf8(getBufferedInputStream());
        }
        if ("--code".equals(srcSpec)) {
            return getNextArgRequired();
        }
        err.println("Unsupported source argument '" + srcSpec + "'.");
        err.println("Pass '-' to read from stdin or '--code <luaSource>', e.g.:");
        err.println("  adb shell cmd apipolicy apply <scriptId> - < local_script.lua");
        return null;
    }

    private static String readAllUtf8(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > ApiPolicyManagerService.MAX_SCRIPT_SOURCE_BYTES) {
                throw new IOException("Script exceeds maximum size of "
                        + ApiPolicyManagerService.MAX_SCRIPT_SOURCE_BYTES + " bytes");
            }
            bos.write(buf, 0, n);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    @Override
    public void onHelp() {
        PrintWriter pw = getOutPrintWriter();
        pw.println("API Policy (apipolicy) commands:");
        pw.println("  help");
        pw.println("      Print this help text.");
        pw.println("  points");
        pw.println("      List all registered hook points and counters.");
        pw.println("  scripts");
        pw.println("      List all configured policy scripts and runtime metrics.");
        pw.println("  show <scriptId>");
        pw.println("      Display the Lua source of a script.");
        pw.println("  validate - | validate --code <luaSource>");
        pw.println("      Validate Lua script syntax and initialization in sandbox.");
        pw.println("  apply [--disabled] <scriptId> -");
        pw.println("      Compile, activate, and persist a Lua script read from stdin.");
        pw.println("  apply [--disabled] <scriptId> --code <luaSource>");
        pw.println("      Compile, activate, and persist an inline Lua snippet.");
        pw.println("  enable <scriptId> | disable <scriptId>");
        pw.println("      Toggle a persisted script on or off.");
        pw.println("  reload <scriptId>");
        pw.println("      Re-initialize a script's Lua VM (resets script-local state).");
        pw.println("  remove <scriptId>");
        pw.println("      Delete a persisted script.");
        pw.println("  logs [scriptId] [limit]");
        pw.println("      Print recent policy.log() and runtime error entries.");
        pw.println("  clear-logs [scriptId]");
        pw.println("      Clear buffered log entries.");
    }
}
