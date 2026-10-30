package com.android.server.ext.apipolicy;

import android.annotation.Nullable;
import android.os.Environment;
import android.util.AtomicFile;
import android.util.JsonReader;
import android.util.JsonWriter;
import android.util.Slog;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Atomic Device-Encrypted (DE) persistence store for API policy scripts under
 * {@code /data/system/apipolicy/scripts.json}.
 */
final class PolicyScriptStore {

    private static final String TAG = "ApiPolicyStore";
    private static final int SCHEMA_VERSION = 1;

    static final class PersistedScript {
        final String scriptId;
        final String source;
        final boolean enabled;
        final long updatedAtMs;

        PersistedScript(String scriptId, String source, boolean enabled, long updatedAtMs) {
            this.scriptId = scriptId;
            this.source = source;
            this.enabled = enabled;
            this.updatedAtMs = updatedAtMs;
        }
    }

    static final class LoadResult {
        final List<PersistedScript> scripts;
        final int rejectedCount;
        @Nullable final String errorMessage;

        LoadResult(List<PersistedScript> scripts, int rejectedCount,
                @Nullable String errorMessage) {
            this.scripts = scripts;
            this.rejectedCount = rejectedCount;
            this.errorMessage = errorMessage;
        }
    }

    private final File mDir;
    private final AtomicFile mAtomicFile;

    PolicyScriptStore() {
        this(new File(Environment.getDataSystemDirectory(), "apipolicy"));
    }

    PolicyScriptStore(File dir) {
        mDir = dir;
        mAtomicFile = new AtomicFile(new File(mDir, "scripts.json"));
    }

    LoadResult loadAll() {
        List<PersistedScript> out = new ArrayList<>();
        int rejectedCount = 0;
        String errorMessage = null;
        if (!mAtomicFile.exists()) {
            return new LoadResult(out, 0, null);
        }

        try (FileInputStream fis = mAtomicFile.openRead();
             JsonReader reader = new JsonReader(
                     new InputStreamReader(fis, StandardCharsets.UTF_8))) {
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if ("version".equals(name)) {
                    int version = reader.nextInt();
                    if (version > SCHEMA_VERSION) {
                        Slog.w(TAG, "Unsupported policy script store version " + version
                                + " (max supported=" + SCHEMA_VERSION + ")");
                        return new LoadResult(new ArrayList<>(), 0,
                                "Unsupported store schema version " + version);
                    }
                } else if ("scripts".equals(name)) {
                    reader.beginArray();
                    while (reader.hasNext()) {
                        PersistedScript item = readScriptItem(reader);
                        if (item != null) {
                            out.add(item);
                        } else {
                            rejectedCount++;
                        }
                    }
                    reader.endArray();
                } else {
                    reader.skipValue();
                }
            }
            reader.endObject();
        } catch (Exception e) {
            Slog.e(TAG, "Failed to read persisted policy scripts", e);
            out.clear();
            errorMessage = "Store read failed (" + e.getClass().getSimpleName() + ")";
        }
        return new LoadResult(out, rejectedCount, errorMessage);
    }

    private static PersistedScript readScriptItem(JsonReader reader) throws IOException {
        String id = null;
        String source = null;
        boolean enabled = false;
        long updatedAtMs = 0L;

        reader.beginObject();
        while (reader.hasNext()) {
            String key = reader.nextName();
            switch (key) {
                case "id" -> id = reader.nextString();
                case "source" -> source = reader.nextString();
                case "enabled" -> enabled = reader.nextBoolean();
                case "updated_at_ms" -> updatedAtMs = reader.nextLong();
                default -> reader.skipValue();
            }
        }
        reader.endObject();

        if (id == null || id.isEmpty() || source == null) {
            return null;
        }
        return new PersistedScript(id, source, enabled, updatedAtMs);
    }

    void saveAll(Collection<PersistedScript> scripts) throws IOException {
        if (!mDir.exists() && !mDir.mkdirs() && !mDir.isDirectory()) {
            throw new IOException("Unable to create policy script store directory");
        }

        FileOutputStream fos = null;
        File baseFile = mAtomicFile.getBaseFile();
        File newFile = new File(baseFile.getPath() + ".new");
        try {
            fos = mAtomicFile.startWrite();
            JsonWriter writer = new JsonWriter(
                    new OutputStreamWriter(fos, StandardCharsets.UTF_8));
            writer.setIndent("  ");
            writer.beginObject();
            writer.name("version").value(SCHEMA_VERSION);
            writer.name("scripts");
            writer.beginArray();
            for (PersistedScript s : scripts) {
                writer.beginObject();
                writer.name("id").value(s.scriptId);
                writer.name("enabled").value(s.enabled);
                writer.name("updated_at_ms").value(s.updatedAtMs);
                writer.name("source").value(s.source);
                writer.endObject();
            }
            writer.endArray();
            writer.endObject();
            writer.flush();
            fos.getFD().sync();
            fos.close();
            fos = null;
            if (!newFile.renameTo(baseFile)) {
                throw new IOException("Failed to commit policy script store");
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to persist policy scripts", e);
            if (fos != null) {
                mAtomicFile.failWrite(fos);
            } else if (newFile.exists() && !newFile.delete()) {
                Slog.e(TAG, "Failed to delete incomplete policy script store");
            }
            if (e instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("Failed to persist policy scripts", e);
        }
    }
}
