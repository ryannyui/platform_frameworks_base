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
import android.os.ServiceSpecificException;
import android.os.UserHandle;
import android.platform.test.annotations.Presubmit;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;

import com.android.internal.ext.apipolicy.HookPointInfo;
import com.android.internal.ext.apipolicy.IApiPolicyListener;
import com.android.internal.ext.apipolicy.PolicyServiceStatus;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@SmallTest
@Presubmit
public class ApiPolicyManagerServiceTest {
    static {
        System.loadLibrary("servicestestjni");
    }

    private File mDir;
    private ApiPolicyManagerService mService;

    @Before
    public void setUp() {
        mDir = new File(InstrumentationRegistry.getContext().getCacheDir(),
                "apipolicy-service-test");
        mService = new ApiPolicyManagerService(InstrumentationRegistry.getContext(),
                new PolicyScriptStore(mDir));
    }

    @After
    public void tearDown() {
        FileUtils.deleteContentsAndDir(mDir);
    }

    @Test
    public void configVersion_increasesOnlyForCommittedChanges() {
        assertEquals(0, mService.getServiceStatusInternal().configVersion);

        assertTrue(mService.upsertScriptInternal("script", "return nil", false).valid);
        assertEquals(1, mService.getServiceStatusInternal().configVersion);

        assertTrue(mService.setScriptEnabledInternal("script", false));
        assertEquals(1, mService.getServiceStatusInternal().configVersion);

        assertTrue(mService.setScriptEnabledInternal("script", true));
        assertEquals(2, mService.getServiceStatusInternal().configVersion);

        assertTrue(mService.reloadScriptInternal("script"));
        assertEquals(3, mService.getServiceStatusInternal().configVersion);

        assertTrue(mService.removeScriptInternal("script"));
        assertEquals(4, mService.getServiceStatusInternal().configVersion);
    }

    @Test
    public void listener_receivesCommittedConfigVersion() throws Exception {
        TestListener listener = new TestListener();
        mService.registerListenerInternal(listener);

        assertTrue(mService.upsertScriptInternal("script", "return nil", false).valid);

        assertTrue(listener.mLatch.await(5, TimeUnit.SECONDS));
        assertEquals(1, listener.mVersion.get());
        mService.unregisterListenerInternal(listener);
        assertTrue(mService.removeScriptInternal("script"));
    }

    @Test
    public void listener_continuesAfterAnotherListenerThrows() throws Exception {
        TestListener throwing = new TestListener();
        throwing.mThrow = true;
        TestListener receiving = new TestListener();
        mService.registerListenerInternal(throwing);
        mService.registerListenerInternal(receiving);

        assertTrue(mService.upsertScriptInternal("script", "return nil", false).valid);

        assertTrue(receiving.mLatch.await(5, TimeUnit.SECONDS));
        assertEquals(1, receiving.mVersion.get());
        mService.unregisterListenerInternal(throwing);
        mService.unregisterListenerInternal(receiving);
        assertTrue(mService.removeScriptInternal("script"));
    }

    @Test
    public void globalEnable_restoresScriptsSkippedDuringLoad() throws Exception {
        new PolicyScriptStore(mDir).saveAll(List.of(
                new PolicyScriptStore.PersistedScript("script",
                        "policy.on(\"test.point\", function(ctx) return nil end)", true, 1L)));
        mService.loadPersistedScripts(true);
        assertNull(mService.getHookPointInternal("test.point"));

        mService.restoreEnabledScripts();

        HookPointInfo point = mService.getHookPointInternal("test.point");
        assertNotNull(point);
        assertEquals(1, point.boundScriptIds.length);
        assertEquals("script", point.boundScriptIds[0]);
        assertTrue(mService.removeScriptInternal("script"));
    }

    @Test
    public void persistenceFailure_doesNotCommitOrAdvanceVersion() throws Exception {
        File blockedDir = new File(InstrumentationRegistry.getContext().getCacheDir(),
                "apipolicy-blocked-store");
        try {
            Files.write(blockedDir.toPath(), "not a directory".getBytes(StandardCharsets.UTF_8));
            ApiPolicyManagerService service = new ApiPolicyManagerService(
                    InstrumentationRegistry.getContext(), new PolicyScriptStore(blockedDir));

            assertThrows(ServiceSpecificException.class,
                    () -> service.upsertScriptInternal("script", "return nil", false));

            PolicyServiceStatus status = service.getServiceStatusInternal();
            assertEquals(0, status.configVersion);
            assertEquals(0, status.loadedScriptCount);
            assertFalse(status.storageHealthy);
        } finally {
            FileUtils.deleteContentsAndDir(blockedDir);
        }
    }

    @Test
    public void enforceSystemUser_rejectsSecondaryUser() {
        ApiPolicyManagerService.enforceSystemUser(UserHandle.getUid(0, 12345));
        assertThrows(SecurityException.class,
                () -> ApiPolicyManagerService.enforceSystemUser(UserHandle.getUid(10, 12345)));
    }

    private static final class TestListener extends IApiPolicyListener.Stub {
        final CountDownLatch mLatch = new CountDownLatch(1);
        final AtomicLong mVersion = new AtomicLong();
        volatile boolean mThrow;

        @Override
        public void onPolicyChanged(long configVersion) {
            if (mThrow) {
                throw new RuntimeException("Test listener failure");
            }
            mVersion.set(configVersion);
            mLatch.countDown();
        }
    }
}
