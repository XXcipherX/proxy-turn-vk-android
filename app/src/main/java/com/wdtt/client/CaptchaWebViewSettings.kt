package com.wdtt.client

import android.annotation.SuppressLint
import android.webkit.WebSettings
import android.webkit.WebView

@SuppressLint("SetJavaScriptEnabled")
internal fun WebView.configureCaptchaWebView(): String {
    settings.apply {
        javaScriptEnabled = true
        domStorageEnabled = true
        mediaPlaybackRequiresUserGesture = false
        loadWithOverviewMode = true
        useWideViewPort = true
        blockNetworkLoads = false
        cacheMode = WebSettings.LOAD_DEFAULT
    }

    // Do not override userAgentString: VK must see the TLS/UA identity of the
    // Android System WebView that is actually rendering the captcha.
    return settings.userAgentString.orEmpty()
}
