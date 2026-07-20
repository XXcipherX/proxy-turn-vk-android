package com.wdtt.client

import android.app.Application
import android.content.Context
import android.util.Log
import com.wireguard.android.backend.GoBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class WdttApplication : Application() {
    @Volatile
    private var backendInstance: GoBackend? = null

    val backend: GoBackend
        get() = getBackend(this)

    override fun onCreate() {
        super.onCreate()
        CoroutineScope(SupervisorJob() + Dispatchers.Main).launch {
            try {
                TunnelManager.running.collect {
                    VpnWidgetProvider.updateAllWidgets(this@WdttApplication)
                }
            } catch (e: Exception) {
                Log.e("WdttApp", "Не удалось обновить виджеты: ${e.message}")
            }
        }

        
        val settingsStore = SettingsStore(this)
        CoroutineScope(SupervisorJob() + Dispatchers.Main).launch {
            try {
                settingsStore.loggingEnabled.collect { enabled ->
                    TunnelManager.isLoggingEnabled = enabled
                }
            } catch (e: Exception) {
                Log.e("WdttApp", "Не удалось отслеживать флаг логирования: ${e.message}")
            }
        }
    }

    fun getBackend(context: Context): GoBackend {
        return backendInstance ?: synchronized(this) {
            backendInstance ?: GoBackend(context.applicationContext).also { backendInstance = it }
        }
    }
}
