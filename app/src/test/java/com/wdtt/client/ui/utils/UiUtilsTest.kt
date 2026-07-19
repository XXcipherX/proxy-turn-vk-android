package com.wdtt.client.ui.utils

import org.junit.Assert.assertEquals
import org.junit.Test

class UiUtilsTest {
    @Test
    fun stripsSupportedVkJoinDomains() {
        val hash = "abcdefghijk"
        val links = listOf(
            "https://vk.com/call/join/$hash",
            "https://m.vk.com/call/join/$hash",
            "https://vk.ru/call/join/$hash",
            "https://m.vk.ru/call/join/$hash",
            "https://vk.me/join/$hash"
        )

        for (link in links) {
            assertEquals(hash, stripVkUrlStatic(link))
        }
    }

    @Test
    fun stripsQueryFragmentAndTrailingSlash() {
        assertEquals("abcdefghijk", stripVkUrlStatic("https://vk.ru/call/join/abcdefghijk/?from=copy#call"))
    }
}
