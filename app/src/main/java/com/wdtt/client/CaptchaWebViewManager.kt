package com.wdtt.client

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

object CaptchaWebViewManager {

    private const val TAG = "CaptchaWV"
    private const val CAPTCHA_TIMEOUT_MS = 20_000L
    private const val WV_CREATE_TIMEOUT_MS = 3000L
    const val ERROR_SLIDER_DETECTED = "slider_detected"

    enum class Step(val stableKey: String, val message: String, val isError: Boolean = false) {
        PAGE_LOADED("captcha_wv_step_2_page", "Страница загружена"),
        CHECKBOX_FOUND("captcha_wv_step_3_checkbox", "Checkbox найден"),
        CHECKBOX_CLICKED("captcha_wv_step_4_click", "Клик выполнен"),
        API_RESPONSE("captcha_wv_step_5_response", "Ответ API получен"),
        SLIDER_DETECTED("captcha_wv_step_5_slider", "Обнаружен слайдер", true)
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val captchaMutex = Mutex()

    @Volatile
    private var isTunnelActive = false

    @Volatile
    private var appContext: Context? = null

    private val pendingResult = AtomicReference<CompletableDeferred<Result<String>>?>(null)
    private val postClickSliderWatcher = AtomicReference<Runnable?>(null)
    private val checkboxSearchStarted = AtomicBoolean(false)

    @Volatile
    private var currentWebView: WebView? = null

    
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
                        window.WdttCaptcha.onApiResponse();
                        if (data.response && data.response.success_token) {
                            window.WdttCaptcha.onSuccess(data.response.success_token);
                        } else if (
                            data.response &&
                            data.response.show_captcha_type === 'slider'
                        ) {
                            window.WdttCaptcha.onSliderDetected('check_response');
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
                            window.WdttCaptcha.onApiResponse();
                            if (data.response && data.response.success_token) {
                                window.WdttCaptcha.onSuccess(data.response.success_token);
                            } else if (
                                data.response &&
                                data.response.show_captcha_type === 'slider'
                            ) {
                                window.WdttCaptcha.onSliderDetected('check_response');
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

    
    
    

    fun onTunnelStart(context: Context) {
        appContext = context.applicationContext
        isTunnelActive = true
        Log.d(TAG, "Туннель активен")
    }

    fun onTunnelStop() {
        isTunnelActive = false
        cancelPendingResult("tunnel stopped")
        destroyCurrentWebView()
        appContext = null
        Log.d(TAG, "Туннель остановлен")
    }

    
    
    

    suspend fun solveCaptchaAsync(redirectUri: String, sessionToken: String, onStep: (Step) -> Unit = {}): String {
        if (!isTunnelActive) throw IllegalStateException("WV не готов — туннель не активен")
        val ctx = appContext ?: throw IllegalStateException("WV не готов — контекст null")

        
        
        return captchaMutex.withLock {
            try {
                withTimeout(CAPTCHA_TIMEOUT_MS) {
                    doSolveCaptcha(ctx, redirectUri, onStep)
                }
            } finally {
                pendingResult.set(null)
                destroyCurrentWebView()
            }
        }
    }

    
    
    

    private suspend fun doSolveCaptcha(context: Context, redirectUri: String, onStep: (Step) -> Unit): String {
        val deferred = CompletableDeferred<Result<String>>()
        pendingResult.set(deferred)

        val webView = createWebViewSync(context, onStep)
            ?: throw IllegalStateException("Не удалось создать WebView")

        Log.d(TAG, "WebView создан ✓")

        
        withContext(Dispatchers.Main) {
            webView.evaluateJavascript(interceptorJSCode, null)
            kotlinx.coroutines.delay(80)
            webView.loadUrl(redirectUri)
        }

        
        try {
            val token = deferred.await().getOrThrow()
            Log.d(TAG, "Капча решена ✓")
            return token
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка: ${e::class.simpleName} — ${e.message}")
            throw e
        }
    }

    
    
    

    private fun createWebViewSync(context: Context, onStep: (Step) -> Unit): WebView? {
        val displayMetrics = context.resources.displayMetrics
        val vw = displayMetrics.widthPixels.coerceAtLeast(1)
        val vh = displayMetrics.heightPixels.coerceAtLeast(1)

        val latch = CountDownLatch(1)
        var webView: WebView? = null

        val createAction = Runnable {
            try {
                val wv = WebView(context.applicationContext)
                wv.apply {
                    val userAgent = configureCaptchaWebView()
                    Log.d(TAG, "System WebView: ${vw}x${vh}, UA: $userAgent")

                    addJavascriptInterface(CaptchaJSBridge(onStep), "WdttCaptcha")

                    webViewClient = object : WebViewClient() {
                        override fun onPageStarted(
                            view: WebView, url: String?, favicon: android.graphics.Bitmap?
                        ) {
                            super.onPageStarted(view, url, favicon)
                            view.evaluateJavascript(interceptorJSCode, null)
                        }

                        override fun onPageFinished(view: WebView, url: String?) {
                            super.onPageFinished(view, url)

                            val isCaptchaPage = url?.let {
                                it.contains("not_robot_captcha") ||
                                it.contains("id.vk.ru/captcha") ||
                                it.contains("not_robot")
                            } ?: false

                            if (isCaptchaPage) {
                                view.evaluateJavascript(interceptorJSCode, null)

                                if (currentWebView === view && isTunnelActive &&
                                    checkboxSearchStarted.compareAndSet(false, true)
                                ) {
                                    Log.d(TAG, "Страница капчи загружена")
                                    reportStep(onStep, Step.PAGE_LOADED)
                                    
                                    val pageLoadDelay = 650L + Random.Default.nextLong(0, 550)
                                    mainHandler.postDelayed({
                                        if (currentWebView === view && isTunnelActive) {
                                            solveCaptchaAutomatedSync(view, onStep)
                                        }
                                    }, pageLoadDelay)
                                }
                            }
                        }

                        override fun shouldInterceptRequest(
                            view: WebView, request: WebResourceRequest
                        ): WebResourceResponse? {
                            return super.shouldInterceptRequest(view, request)
                        }

                        override fun onReceivedSslError(
                            view: WebView,
                            handler: android.webkit.SslErrorHandler,
                            error: android.net.http.SslError
                        ) {
                            
                            val url = error.url ?: ""
                            if (url.contains("vk.ru") || url.contains("vk.com") || url.contains("okcdn.ru")) {
                                handler.proceed()
                            } else {
                                handler.cancel()
                                Log.w(TAG, "SSL error rejected for: $url")
                            }
                        }
                    }

                    webChromeClient = WebChromeClient()

                    measure(
                        View.MeasureSpec.makeMeasureSpec(vw, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(vh, View.MeasureSpec.EXACTLY)
                    )
                    layout(0, 0, vw, vh)
                    onResume()
                }
                webView = wv
                currentWebView = wv
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка создания WebView: ${e.message}")
                webView = null
            } finally {
                latch.countDown()
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            createAction.run()
        } else {
            mainHandler.post(createAction)
        }

        val ok = latch.await(WV_CREATE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        if (!ok) {
            Log.e(TAG, "Таймаут создания WebView")
            return null
        }
        return webView
    }

    private fun destroyCurrentWebView() {
        val wv = currentWebView ?: return
        currentWebView = null
        checkboxSearchStarted.set(false)
        postClickSliderWatcher.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }

        val destroyAction = Runnable {
            try {
                wv.stopLoading()
                wv.loadUrl("about:blank")
                try { wv.removeJavascriptInterface("WdttCaptcha") } catch (_: Exception) {}
                wv.webViewClient = WebViewClient()
                wv.webChromeClient = null
                wv.onPause()
                wv.removeAllViews()
                wv.destroy()
                Log.d(TAG, "WebView уничтожен ✓")
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка уничтожения: ${e.message}")
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            destroyAction.run()
        } else {
            val latch = CountDownLatch(1)
            mainHandler.post {
                try { destroyAction.run() } finally { latch.countDown() }
            }
            latch.await(2000, TimeUnit.MILLISECONDS)
        }
    }

    
    
    
    
    
    
    
    
    
    
    
    

    private fun solveCaptchaAutomatedSync(webView: WebView, onStep: (Step) -> Unit) {
        if (currentWebView !== webView || !isTunnelActive) return

        
        
        val findLabelJS = """
            (function() {
                var slider = document.querySelector(
                    '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
                    '.vkc__SliderCaptcha-module__description, ' +
                    '.vkc__KaleidoscopeScreen-module__captchaId'
                );
                if (slider) return '${ERROR_SLIDER_DETECTED}';

                // Приоритет: label обёртка (самый большой кликабельный элемент)
                var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
                // Fallback: прямой поиск по ID
                if (!el) el = document.querySelector('label[for="not-robot-captcha-checkbox"]');
                // Fallback: сам чекбокс
                if (!el) el = document.getElementById('not-robot-captcha-checkbox');
                if (!el) return 'not_found';
                
                var rect = el.getBoundingClientRect();
                var style = window.getComputedStyle(el);
                if (rect.width < 5 || rect.height < 5 ||
                    style.display === 'none' || style.visibility === 'hidden') {
                    return 'not_found';
                }
                // Возвращаем left,top,width,height — чтобы кликнуть в РАНДОМНУЮ точку
                return rect.left + ',' + rect.top + ',' + rect.width + ',' + rect.height;
            })();
        """.trimIndent()

        webView.evaluateJavascript(findLabelJS) { rawValue ->
            val result = rawValue?.replace("\"", "") ?: ""
            Log.d(TAG, "Label чекбокса: $result")

            if (currentWebView !== webView || !isTunnelActive) return@evaluateJavascript

            if (result == ERROR_SLIDER_DETECTED) {
                Log.i(TAG, "Обнаружен слайдер — fallback на ручной WebView")
                reportStep(onStep, Step.SLIDER_DETECTED)
                notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
                return@evaluateJavascript
            }

            if (result == "not_found" || result.split(",").size < 4) {
                Log.w(TAG, "Label не найден — JS-клик (fallback)")
                val jsClick = """
                    (function() {
                        var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
                        if (!el) el = document.getElementById('not-robot-captcha-checkbox');
                        if (el) { el.click(); return 'clicked'; }
                        return 'nothing';
                    })();
                """.trimIndent()
                webView.evaluateJavascript(jsClick) { clickResult ->
                    if ((clickResult ?: "").replace("\"", "") == "clicked") {
                        reportStep(onStep, Step.CHECKBOX_FOUND)
                        reportStep(onStep, Step.CHECKBOX_CLICKED)
                        startPostClickSliderWatcher(webView, onStep)
                    } else {
                        Log.d(TAG, "Checkbox пока не найден, повторный поиск")
                        scheduleCheckboxSearch(webView, onStep)
                    }
                }
                return@evaluateJavascript
            }

            val parts = result.split(",")
            val left = parts[0].toFloatOrNull()
            val top = parts[1].toFloatOrNull()
            val width = parts[2].toFloatOrNull()
            val height = parts[3].toFloatOrNull()
            if (left == null || top == null || width == null || height == null) {
                Log.d(TAG, "Координаты checkbox ещё не готовы, повторный поиск")
                scheduleCheckboxSearch(webView, onStep)
                return@evaluateJavascript
            }
            reportStep(onStep, Step.CHECKBOX_FOUND)

            
            
            val randX = left + width * (0.15f + Random.Default.nextFloat() * 0.7f)
            val randY = top + height * (0.25f + Random.Default.nextFloat() * 0.5f)

            Log.d(TAG, "Клик: (${randX.toInt()}, ${randY.toInt()}) в зоне ${width.toInt()}x${height.toInt()}")

            val thinkDelay = 420L + Random.Default.nextLong(0, 260)

            mainHandler.postDelayed({
                if (currentWebView === webView && isTunnelActive) {
                    simulateHumanTouch(webView, randX, randY)
                    reportStep(onStep, Step.CHECKBOX_CLICKED)
                    startPostClickSliderWatcher(webView, onStep)
                }
            }, thinkDelay)
        }
    }

    private fun scheduleCheckboxSearch(webView: WebView, onStep: (Step) -> Unit) {
        mainHandler.postDelayed({
            if (currentWebView === webView && isTunnelActive) {
                solveCaptchaAutomatedSync(webView, onStep)
            }
        }, 500L)
    }

    private fun startPostClickSliderWatcher(webView: WebView, onStep: (Step) -> Unit) {
        postClickSliderWatcher.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }

        var attemptsLeft = 14
        val watcher = object : Runnable {
            override fun run() {
                if (currentWebView !== webView || !isTunnelActive) return

                val detectSliderJS = """
                    (function() {
                        var slider = document.querySelector(
                            '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
                            '.vkc__SliderCaptcha-module__description, ' +
                            '.vkc__KaleidoscopeScreen-module__captchaId, ' +
                            '.vkc__SwipeButton-module__track'
                        );
                        if (slider) return 'slider';

                        var success = document.querySelector(
                            '[class*="success"], [class*="Success"], [class*="passed"], [class*="Passed"]'
                        );
                        if (success) return 'success_ui';

                        return 'none';
                    })();
                """.trimIndent()

                webView.evaluateJavascript(detectSliderJS) { rawValue ->
                    if (currentWebView !== webView || !isTunnelActive) return@evaluateJavascript

                    val result = rawValue?.replace("\"", "") ?: "none"
                    when (result) {
                        "slider" -> {
                            Log.i(TAG, "После checkbox появился слайдер — fallback на ручной WebView")
                            reportStep(onStep, Step.SLIDER_DETECTED)
                            notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
                        }
                        "success_ui" -> {
                            postClickSliderWatcher.set(null)
                        }
                        else -> {
                            attemptsLeft--
                            if (attemptsLeft > 0) {
                                mainHandler.postDelayed(this, 350L)
                            } else {
                                postClickSliderWatcher.set(null)
                            }
                        }
                    }
                }
            }
        }

        postClickSliderWatcher.set(watcher)
        mainHandler.postDelayed(watcher, 450L)
    }

    

    private fun simulateHumanTouch(webView: WebView, cssX: Float, cssY: Float) {
        if (currentWebView !== webView) return

        val density = webView.resources.displayMetrics.density
        val physX = cssX * density
        val physY = cssY * density
        val downTime = SystemClock.uptimeMillis()

        
        val pressure = 0.5f + Random.Default.nextFloat() * 0.4f

        val downEvent = MotionEvent.obtain(
            downTime, downTime, MotionEvent.ACTION_DOWN, physX, physY, pressure, 1f, 0, 1f, 1f, 0, 0
        )
        downEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
        webView.dispatchTouchEvent(downEvent)
        downEvent.recycle()

        
        val holdTime = 80L + Random.Default.nextLong(0, 100)

        mainHandler.postDelayed({
            if (currentWebView === webView) {
                
                val jitterX = physX + (-1f + Random.Default.nextFloat() * 2f) * density
                val jitterY = physY + (-0.5f + Random.Default.nextFloat() * 1f) * density

                val upEvent = MotionEvent.obtain(
                    downTime, SystemClock.uptimeMillis(), MotionEvent.ACTION_UP,
                    jitterX, jitterY, 0f, 1f, 0, 1f, 1f, 0, 0
                )
                upEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
                webView.dispatchTouchEvent(upEvent)
                upEvent.recycle()
            }
        }, holdTime)
    }

    
    
    

    private class CaptchaJSBridge(private val onStep: (Step) -> Unit) {
        @JavascriptInterface
        fun onApiResponse() {
            Log.d(TAG, "JS: ответ captchaNotRobot.check получен")
            reportStep(onStep, Step.API_RESPONSE)
        }

        @JavascriptInterface
        fun onSuccess(token: String) {
            Log.d(TAG, "JS: success_token получен (${token.length} символов)")
            notifyResult(Result.success(token))
        }

        @JavascriptInterface
        fun onSliderDetected(source: String) {
            Log.i(TAG, "JS: обнаружен slider после auto-step ($source)")
            reportStep(onStep, Step.SLIDER_DETECTED)
            notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
        }

        @JavascriptInterface
        fun onError(error: String) {
            Log.e(TAG, "JS: ошибка — $error")
            notifyResult(Result.failure(Exception("VK: $error")))
        }
    }

    private fun reportStep(onStep: (Step) -> Unit, step: Step) {
        try {
            onStep(step)
        } catch (e: Exception) {
            Log.w(TAG, "Не удалось записать этап ${step.name}: ${e.message}")
        }
    }

    private fun notifyResult(result: Result<String>) {
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) {
            deferred.complete(result)
        }
    }

    private fun cancelPendingResult(reason: String) {
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) {
            deferred.complete(Result.failure(CancellationException(reason)))
        }
    }
}
