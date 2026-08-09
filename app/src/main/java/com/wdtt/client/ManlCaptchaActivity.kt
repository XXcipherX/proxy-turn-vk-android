package com.wdtt.client

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.ViewGroup
import android.webkit.*
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView

class ManlCaptchaActivity : ComponentActivity() {
    private val interceptorJSCode = """
        (function() {
            if (window.__wdtt_interceptor_installed) return;
            window.__wdtt_interceptor_installed = true;

            const origFetch = window.fetch;
            window.fetch = async function() {
                const args = arguments;
                const url = args[0] || '';
                if (typeof url === 'string' && url.includes('captchaNotRobot.check')) {
                    const response = await origFetch.apply(this, args);
                    const clone = response.clone();
                    try {
                        const data = await clone.json();
                        if (data.response && data.response.success_token) {
                            window.WdttCaptcha.onSuccess(data.response.success_token);
                        } else if (data.error) {
                            window.WdttCaptcha.onError(JSON.stringify(data.error));
                        }
                    } catch(e) {}
                    return response;
                }
                return origFetch.apply(this, args);
            };

            const origXHROpen = XMLHttpRequest.prototype.open;
            const origXHRSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this._wdtt_url = url;
                return origXHROpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                const xhr = this;
                if (xhr._wdtt_url && xhr._wdtt_url.includes('captchaNotRobot.check')) {
                    xhr.addEventListener('load', function() {
                        try {
                            const data = JSON.parse(xhr.responseText);
                            if (data.response && data.response.success_token) {
                                window.WdttCaptcha.onSuccess(data.response.success_token);
                            } else if (data.error) {
                                window.WdttCaptcha.onError(JSON.stringify(data.error));
                            }
                        } catch(e) {}
                    });
                }
                return origXHRSend.apply(this, arguments);
            };
        })();
    """.trimIndent()

    private val hideElementsJSCode = """
        (function() {
            document.addEventListener('click', function(e) {
                if (e.target.closest('.vkc__ModalCardBase-module__dismiss')) {
                    window.WdttCaptcha.onCancelAndStop();
                }
            });

            const style = document.createElement('style');
            style.innerHTML = `
                .vkc__VisuallyHiddenModalOverlay-module__host,
                .vkc__ModalOverlay-module__host,
                .vkc__KaleidoscopeScreen-module__logoBlock,
                .vkc__KaleidoscopeScreen-module__captchaId,
                .vkc__SliderCaptcha-module__descriptionLink,
                .vkc__SliderCaptcha-module__changeTypeButton {
                    display: none !important;
                }

                body, html, .vkc__ModalCard-module__host, .vkc__AppRoot-module__host, .vkui__root {
                    background: transparent !important;
                    box-shadow: none !important;
                }

                .vkc__ModalCardBase-module__container {
                    background: #000000 !important;
                    box-shadow: none !important;
                }

                .vkc__ModalCardBase-module__dismiss {
                    color: #ef4444 !important;
                    transform: scale(0.8) translateX(-12px) !important;
                }
                .vkc__ModalCardBase-module__dismiss svg {
                    fill: #ef4444 !important;
                }

                .vkc__RefreshButton-module__text,
                .vkc__SliderCaptcha-module__description {
                    color: #ffffff !important;
                }

                .vkc__SwipeButton-module__track {
                    background-color: #ffffff !important;
                }

                .vkc__SwipeButton-module__track span {
                    color: #0000FF !important;
                }
            `;
            document.head.appendChild(style);
        })();
    """.trimIndent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ManlCaptchaWebViewManager.activeActivity = this
        MainActivity.isForeground = true
        val redirectUri = intent.getStringExtra("redirectUri") ?: return finish()

        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Box(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier.align(Alignment.Center),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        var isLoading by rememberSaveable { mutableStateOf(true) }

                        Box {
                            Surface(
                                modifier = Modifier.fillMaxSize(),
                                color = Color.Transparent,
                                tonalElevation = 0.dp,
                                shadowElevation = 0.dp
                            ) {
                                AndroidView(
                                    modifier = Modifier.fillMaxSize(),
                                    factory = { ctx ->
                                        WebView(ctx).apply {
                                            setBackgroundColor(android.graphics.Color.TRANSPARENT)
                                            layoutParams = ViewGroup.LayoutParams(
                                                ViewGroup.LayoutParams.MATCH_PARENT,
                                                ViewGroup.LayoutParams.MATCH_PARENT
                                            )
                                            val userAgent = configureCaptchaWebView()
                                            Log.d("ManlCaptchaWV", "System WebView UA: $userAgent")

                                            addJavascriptInterface(object {
                                                @JavascriptInterface
                                                fun onSuccess(token: String) {
                                                    Log.d("ManlCaptchaWV", "Token received")
                                                    ManlCaptchaWebViewManager.notifyResult(Result.success(token))
                                                    finish()
                                                }
                                                @JavascriptInterface
                                                fun onError(err: String) {
                                                    Log.e("ManlCaptchaWV", "Error: $err")
                                                    ManlCaptchaWebViewManager.notifyResult(Result.failure(Exception("VK Captcha error: ${'$'}err")))
                                                    finish()
                                                }
                                                @JavascriptInterface
                                                fun onCancelAndStop() {
                                                    Log.d("ManlCaptchaWV", "User clicked VK Close. Stopping tunnel.")
                                                    TunnelManager.stop()
                                                    ManlCaptchaWebViewManager.notifyResult(Result.failure(Exception("Cancelled and stopped by user")))
                                                    finish()
                                                }
                                            }, "WdttCaptcha")

                                            webViewClient = object : WebViewClient() {
                                                override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                                                    super.onPageStarted(view, url, favicon)
                                                    view?.evaluateJavascript(interceptorJSCode, null)
                                                }
                                                override fun onPageFinished(view: WebView?, url: String?) {
                                                    super.onPageFinished(view, url)
                                                    view?.evaluateJavascript(interceptorJSCode, null)
                                                    view?.evaluateJavascript(hideElementsJSCode, null)
                                                    isLoading = false
                                                }
                                            }
                                            webChromeClient = WebChromeClient()
                                            loadUrl(redirectUri)
                                        }
                                    }
                                )
                            }

                            if (isLoading) {
                                CircularProgressIndicator(
                                    modifier = Modifier.align(Alignment.Center).size(48.dp),
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        MainActivity.isForeground = false
        if (ManlCaptchaWebViewManager.activeActivity === this) {
            ManlCaptchaWebViewManager.activeActivity = null
        }
    }
}
