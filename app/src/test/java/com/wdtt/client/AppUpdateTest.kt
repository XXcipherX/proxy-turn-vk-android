package com.wdtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdateTest {
    @Test
    fun dottedWorkflowBuildIsNewer() {
        assertTrue(isNewerVersion("1.2.4.56", "v1.2.4.57"))
        assertFalse(isNewerVersion("1.2.4.57", "v1.2.4.57"))
        assertFalse(isNewerVersion("1.2.4.58", "v1.2.4.57"))
    }

    @Test
    fun sourceVersionUpgradeWinsOverBuildNumber() {
        assertTrue(isNewerVersion("1.2.4.99999", "v1.2.5.1"))
        assertFalse(isNewerVersion("1.2.5.1", "v1.2.4.99999"))
    }

    @Test
    fun legacyHyphenatedTagsRemainComparable() {
        assertTrue(isNewerVersion("1.2.4", "v1.2.4-56"))
        assertTrue(isNewerVersion("1.2.4-56", "v1.2.4.57"))
        assertFalse(isNewerVersion("1.2.4.57", "v1.2.4-56"))
    }

    @Test
    fun invalidRemoteVersionDoesNotTriggerUpdate() {
        assertFalse(isNewerVersion("1.2.4.56", "latest"))
    }
}
