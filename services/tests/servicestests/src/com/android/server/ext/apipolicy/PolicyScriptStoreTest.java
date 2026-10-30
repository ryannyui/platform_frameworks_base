/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.ext.apipolicy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.os.FileUtils;
import android.platform.test.annotations.Presubmit;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

@SmallTest
@Presubmit
public class PolicyScriptStoreTest {
    private File mDir;
    private PolicyScriptStore mStore;

    @Before
    public void setUp() {
        mDir = new File(InstrumentationRegistry.getContext().getCacheDir(),
                "apipolicy-store-test");
        mStore = new PolicyScriptStore(mDir);
    }

    @After
    public void tearDown() {
        FileUtils.deleteContentsAndDir(mDir);
    }

    @Test
    public void loadAll_missingFileIsHealthyAndEmpty() {
        PolicyScriptStore.LoadResult result = mStore.loadAll();

        assertTrue(result.scripts.isEmpty());
        assertEquals(0, result.rejectedCount);
        assertNull(result.errorMessage);
    }

    @Test
    public void saveAllAndLoadAll_roundTripsScripts() throws Exception {
        mStore.saveAll(List.of(
                new PolicyScriptStore.PersistedScript(
                        "first", "policy.log(\"hello\\n世界\")", true, 1234L),
                new PolicyScriptStore.PersistedScript("second", "return nil", false, 5678L)));

        PolicyScriptStore.LoadResult result = new PolicyScriptStore(mDir).loadAll();

        assertNull(result.errorMessage);
        assertEquals(0, result.rejectedCount);
        assertEquals(2, result.scripts.size());
        assertScript(result.scripts.get(0), "first", "policy.log(\"hello\\n世界\")",
                true, 1234L);
        assertScript(result.scripts.get(1), "second", "return nil", false, 5678L);
    }

    @Test
    public void loadAll_rejectsInvalidItemsButKeepsValidScripts() throws Exception {
        writeStore("{\"version\":1,\"scripts\":["
                + "{\"id\":\"ok\",\"source\":\"return nil\",\"enabled\":false,"
                + "\"updated_at_ms\":7},"
                + "{\"id\":\"missing-source\",\"enabled\":true}]}");

        PolicyScriptStore.LoadResult result = mStore.loadAll();

        assertNull(result.errorMessage);
        assertEquals(1, result.rejectedCount);
        assertEquals(1, result.scripts.size());
        assertScript(result.scripts.get(0), "ok", "return nil", false, 7L);
    }

    @Test
    public void loadAll_malformedJsonReportsReadError() throws Exception {
        writeStore("{\"version\":1,\"scripts\":["
                + "{\"id\":\"partial\",\"source\":\"return nil\"},");

        PolicyScriptStore.LoadResult result = mStore.loadAll();

        assertNotNull(result.errorMessage);
        assertTrue(result.scripts.isEmpty());
    }

    @Test
    public void loadAll_unsupportedSchemaReportsError() throws Exception {
        writeStore("{\"version\":2,\"scripts\":[]}");

        PolicyScriptStore.LoadResult result = mStore.loadAll();

        assertNotNull(result.errorMessage);
        assertTrue(result.errorMessage.contains("schema version 2"));
        assertTrue(result.scripts.isEmpty());
    }

    @Test
    public void loadAll_restoresLegacyBackup() throws Exception {
        mStore.saveAll(List.of(
                new PolicyScriptStore.PersistedScript("backup", "return nil", true, 42L)));
        File baseFile = new File(mDir, "scripts.json");
        File backupFile = new File(mDir, "scripts.json.bak");
        assertTrue(baseFile.renameTo(backupFile));

        PolicyScriptStore.LoadResult result = new PolicyScriptStore(mDir).loadAll();

        assertNull(result.errorMessage);
        assertEquals(1, result.scripts.size());
        assertScript(result.scripts.get(0), "backup", "return nil", true, 42L);
        assertTrue(baseFile.exists());
        assertFalse(backupFile.exists());
    }

    @Test
    public void saveAll_renameFailureIsPropagated() throws Exception {
        assertTrue(mDir.mkdirs() || mDir.isDirectory());
        File baseFile = new File(mDir, "scripts.json");
        assertTrue(baseFile.mkdir());

        assertThrows(IOException.class, () -> mStore.saveAll(List.of()));

        assertTrue(baseFile.isDirectory());
        assertFalse(new File(mDir, "scripts.json.new").exists());
    }

    @Test
    public void saveAll_failureIsPropagated() throws Exception {
        assertTrue(mDir.getParentFile().exists());
        Files.write(mDir.toPath(), "not a directory".getBytes(StandardCharsets.UTF_8));

        assertThrows(IOException.class, () -> mStore.saveAll(List.of()));
        assertFalse(new File(mDir, "scripts.json").exists());
    }

    private void writeStore(String contents) throws IOException {
        assertTrue(mDir.mkdirs() || mDir.isDirectory());
        Files.write(new File(mDir, "scripts.json").toPath(),
                contents.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertScript(PolicyScriptStore.PersistedScript actual, String id,
            String source, boolean enabled, long updatedAtMs) {
        assertEquals(id, actual.scriptId);
        assertEquals(source, actual.source);
        assertEquals(enabled, actual.enabled);
        assertEquals(updatedAtMs, actual.updatedAtMs);
    }
}
