package com.wdtt.client

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.net.URLDecoder
import java.util.Locale

object VkCaptchaProfileStore {
    private const val TAG = "VkCaptchaProfile"
    private const val PROFILE_FILE = "vk_profile.json"

    @Synchronized
    fun updateFromCapture(
        context: Context,
        rawDevice: String?,
        rawBrowserFp: String?,
        rawUserAgent: String?,
        source: String
    ) {
        val deviceJson = decodeFormValue(rawDevice).trim()
        val browserFp = decodeFormValue(rawBrowserFp).trim()
        val userAgent = decodeFormValue(rawUserAgent).trim()

        if (deviceJson.isEmpty() && browserFp.isEmpty()) {
            Log.d(TAG, "capture skipped: empty fields from $source")
            return
        }

        val file = File(context.filesDir, PROFILE_FILE)
        val existing = readExisting(file)
        val existingDevice = decodeFormValue(
            existing.optString("device_json").ifEmpty { existing.optString("device") }
        )
        val mergedDevice = deviceJson.ifEmpty { existingDevice }
        val mergedBrowserFp = browserFp.ifEmpty { decodeFormValue(existing.optString("browser_fp")) }
        val mergedUserAgent = userAgent.ifEmpty { existing.optString("user_agent") }

        if (mergedDevice.isEmpty() && mergedBrowserFp.isEmpty()) {
            Log.d(TAG, "capture skipped: no usable merged fields from $source")
            return
        }

        val profile = browserProfileForUserAgent(mergedUserAgent)
        val out = JSONObject().apply {
            put("user_agent", profile.userAgent)
            put("sec_ch_ua", profile.secChUa)
            put("sec_ch_ua_mobile", profile.secChUaMobile)
            put("sec_ch_ua_platform", profile.secChUaPlatform)
            put("device_json", mergedDevice)
            put("browser_fp", mergedBrowserFp)
            put("captured_at", System.currentTimeMillis() / 1000.0)
        }

        try {
            val tmp = File(file.parentFile, "$PROFILE_FILE.tmp")
            tmp.writeText(out.toString(), Charsets.UTF_8)
            if (!tmp.renameTo(file)) {
                file.writeText(out.toString(), Charsets.UTF_8)
                tmp.delete()
            }
            Log.i(
                TAG,
                "saved captured profile from $source " +
                    "(device=${mergedDevice.length}c, browser_fp=${mergedBrowserFp.length}c, ua=${profile.userAgent.length}c)"
            )
        } catch (e: Exception) {
            Log.w(TAG, "failed to save captured profile from $source: ${e.message}")
        }
    }

    private fun readExisting(file: File): JSONObject {
        return try {
            if (file.exists()) JSONObject(file.readText(Charsets.UTF_8)) else JSONObject()
        } catch (_: Exception) {
            JSONObject()
        }
    }

    private fun decodeFormValue(value: String?): String {
        val v = value?.trim().orEmpty()
        if (v.isEmpty()) return ""
        return try {
            URLDecoder.decode(v, "UTF-8")
        } catch (_: Exception) {
            v
        }
    }

    private data class CapturedProfile(
        val userAgent: String,
        val secChUa: String,
        val secChUaMobile: String,
        val secChUaPlatform: String
    )

    private fun browserProfileForUserAgent(rawUserAgent: String): CapturedProfile {
        val ua = rawUserAgent.ifBlank {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
        }
        val lower = ua.lowercase(Locale.US)
        val chromeMajor = Regex("""(?:Chrome|Chromium|Edg)/(\d+)""").find(ua)
            ?.groupValues
            ?.getOrNull(1)
            ?: "146"
        val isMobile = lower.contains(" mobile") || lower.contains("android") || lower.contains("iphone")
        val platform = when {
            lower.contains("android") -> "\"Android\""
            lower.contains("iphone") || lower.contains("ipad") -> "\"iOS\""
            lower.contains("macintosh") -> "\"macOS\""
            lower.contains("linux") || lower.contains("x11") -> "\"Linux\""
            else -> "\"Windows\""
        }
        val brand = if (lower.contains("edg/")) "Microsoft Edge" else "Google Chrome"
        return CapturedProfile(
            userAgent = ua,
            secChUa = "\"Chromium\";v=\"$chromeMajor\", \"Not-A.Brand\";v=\"24\", \"$brand\";v=\"$chromeMajor\"",
            secChUaMobile = if (isMobile) "?1" else "?0",
            secChUaPlatform = platform
        )
    }
}
