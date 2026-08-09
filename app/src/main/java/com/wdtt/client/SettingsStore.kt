package com.wdtt.client

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class SettingsStore(context: Context) {
    private val appContext = context.applicationContext
    companion object {
        private val Context.dataStore by preferencesDataStore("settings")
        private val ACTIVE_PROFILE = intPreferencesKey("active_profile")
        private val SHOW_SYSTEM_APPS = booleanPreferencesKey("show_system_apps")
        private val LOGGING_ENABLED = booleanPreferencesKey("logging_enabled")
        private val WDTT_LINK = stringPreferencesKey("wdtt_link")
        private val WDTT_LINK_MODE = booleanPreferencesKey("wdtt_link_mode")
        private val CONNECTION_PROFILES_ENCRYPTED = stringPreferencesKey("connection_profiles_encrypted")
        private val ACTIVE_CONNECTION_PROFILE_ID = stringPreferencesKey("active_connection_profile_id")

        private val PEER = stringPreferencesKey("peer")
        private val VK_HASHES = stringPreferencesKey("vk_hashes")
        private val SECONDARY_VK_HASH = stringPreferencesKey("secondary_vk_hash")
        private val WORKERS_PER_HASH = intPreferencesKey("workers_per_hash")
        private val LISTEN_PORT = intPreferencesKey("listen_port")
        private val MANUAL_PORTS_ENABLED = booleanPreferencesKey("manual_ports_enabled")
        private val SERVER_DTLS_PORT = intPreferencesKey("server_dtls_port")
        private val SERVER_WG_PORT = intPreferencesKey("server_wg_port")
        private val NO_DTLS = booleanPreferencesKey("no_dtls")

        private val EXCLUDED_APPS = stringPreferencesKey("excluded_apps")

        private val CONNECTION_PASSWORD = stringPreferencesKey("connection_password")
        private val CONNECTION_PASSWORD_ENCRYPTED = stringPreferencesKey("connection_password_encrypted")

        private val VK_AUTH_MODE = stringPreferencesKey("vk_auth_mode") 
        private val OBFS_MODE = stringPreferencesKey("obfs_mode") 
        private val CAPTCHA_MODE = stringPreferencesKey("captcha_mode") 
        private val CAPTCHA_SOLVE_METHOD = stringPreferencesKey("captcha_solve_method") 
        private val CAPTCHA_WBV_SOLVE_METHOD = stringPreferencesKey("captcha_wbv_solve_method") 
        
        
        private val IS_WHITELIST = booleanPreferencesKey("is_whitelist")
        private val SPLIT_TUNNEL_WHITELIST_MIGRATED = booleanPreferencesKey("split_tunnel_whitelist_migrated")

        
        private val THEME_MODE = stringPreferencesKey("theme_mode") 
        private val IS_DYNAMIC_COLOR = booleanPreferencesKey("is_dynamic_color")
        private val THEME_PALETTE = stringPreferencesKey("theme_palette")

        
        private val ACTIVE_CLIENT_IDS = stringPreferencesKey("active_client_ids")

        private val UPDATE_LAST_CHECK_AT = longPreferencesKey("update_last_check_at")
        private val UPDATE_LATEST_VERSION = stringPreferencesKey("update_latest_version")
        private val UPDATE_LAST_ERROR = stringPreferencesKey("update_last_error")
        private val UPDATE_CHECK_INTERVAL_HOURS = intPreferencesKey("update_check_interval_hours")
        private val UPDATE_POSTPONE_UNTIL = longPreferencesKey("update_postpone_until")
        private val UPDATE_POSTPONE_VERSION = stringPreferencesKey("update_postpone_version")
        private val UPDATE_DIALOG_LAST_SHOWN_VERSION = stringPreferencesKey("update_dialog_last_shown_version")
        private val UPDATE_DIALOG_LAST_SHOWN_AT = longPreferencesKey("update_dialog_last_shown_at")
        private val UPDATE_DIALOG_LAST_ACTION_VERSION = stringPreferencesKey("update_dialog_last_action_version")
        private val UPDATE_DIALOG_LAST_ACTION = stringPreferencesKey("update_dialog_last_action")
        private val UPDATE_DIALOG_LAST_ACTION_AT = longPreferencesKey("update_dialog_last_action_at")

        private val CLIENT_ID_CHECK_RESULTS = stringPreferencesKey("client_id_check_results")

        private fun <T> getProfileKey(baseKey: Preferences.Key<T>, profile: Int): Preferences.Key<T> {
            if (profile == 0) return baseKey
            val newName = "${baseKey.name}_$profile"
            @Suppress("UNCHECKED_CAST")
            return when (baseKey) {
                PEER, VK_HASHES, SECONDARY_VK_HASH, EXCLUDED_APPS, CONNECTION_PASSWORD, CONNECTION_PASSWORD_ENCRYPTED, VK_AUTH_MODE, OBFS_MODE, CAPTCHA_MODE, CAPTCHA_SOLVE_METHOD, CAPTCHA_WBV_SOLVE_METHOD, WDTT_LINK, CONNECTION_PROFILES_ENCRYPTED, ACTIVE_CONNECTION_PROFILE_ID, ACTIVE_CLIENT_IDS -> stringPreferencesKey(newName) as Preferences.Key<T>
                WORKERS_PER_HASH, LISTEN_PORT, SERVER_DTLS_PORT, SERVER_WG_PORT -> intPreferencesKey(newName) as Preferences.Key<T>
                MANUAL_PORTS_ENABLED, NO_DTLS, IS_WHITELIST, WDTT_LINK_MODE -> booleanPreferencesKey(newName) as Preferences.Key<T>
                else -> throw IllegalArgumentException("Unsupported key type: ${baseKey.name}")
            }
        }
    }

    private val dataStore = appContext.dataStore
    private val secureStore = SecureStringStore(appContext)

    init {
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            purgeLegacyDeploySettings()
            purgeRemovedTunnelSettings()
            migrateSecretsToKeystore()
            migrateLegacyWhitelistMode()
            migrateLegacyWdttLink()
        }
    }

    val activeProfile: Flow<Int> = dataStore.data.map { it[ACTIVE_PROFILE] ?: 0 }
    val showSystemApps: Flow<Boolean> = dataStore.data.map { it[SHOW_SYSTEM_APPS] ?: true }
    val loggingEnabled: Flow<Boolean> = dataStore.data.map { it[LOGGING_ENABLED] ?: true }
    val wdttLink: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WDTT_LINK, profile)] ?: ""
    }
    val wdttLinkMode: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WDTT_LINK_MODE, profile)] ?: false
    }
    val connectionProfiles: Flow<List<ConnectionProfile>> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val encrypted = prefs[getProfileKey(CONNECTION_PROFILES_ENCRYPTED, profile)]
        ConnectionProfile.decodeList(secureStore.decrypt(encrypted).orEmpty())
    }
    val activeConnectionProfileId: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, profile)] ?: ""
    }

    val peer: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PEER, profile)] ?: ""
    }
    val vkHashes: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VK_HASHES, profile)] ?: ""
    }
    val secondaryVkHash: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SECONDARY_VK_HASH, profile)] ?: ""
    }
    val workersPerHash: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 16
    }
    val listenPort: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(LISTEN_PORT, profile)] ?: 9000
    }
    val manualPortsEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false
    }
    val serverDtlsPort: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SERVER_DTLS_PORT, profile)] ?: 56000
    }
    val serverWgPort: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SERVER_WG_PORT, profile)] ?: 56001
    }

    val excludedApps: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(EXCLUDED_APPS, profile)] ?: ""
    }

    val connectionPassword: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, profile)
    }

    val vkAuthMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VK_AUTH_MODE, profile)] ?: "vkcalls"
    }
    val obfsMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val mode = prefs[getProfileKey(OBFS_MODE, profile)]
        if (mode.isNullOrBlank()) "audio" else mode
    }
    
    val captchaMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto"
    }
    val captchaSolveMethod: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto"
    }
    val captchaWbvSolveMethod: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] ?: "auto"
    }

    
    val isWhitelist: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(IS_WHITELIST, profile)] ?: false
    }

    
    val themeMode: Flow<String> = dataStore.data.map { it[THEME_MODE] ?: "system" }
    val isDynamicColor: Flow<Boolean> = dataStore.data.map { it[IS_DYNAMIC_COLOR] ?: (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) }
    val themePalette: Flow<String> = dataStore.data.map { it[THEME_PALETTE] ?: "indigo" }

    
    val activeClientIds: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: "8202606,6287487"
    }
    val clientIdCheckResults: Flow<String> = dataStore.data.map { prefs ->
        prefs[CLIENT_ID_CHECK_RESULTS] ?: "{}"
    }

    val updateLastCheckAt: Flow<Long> = dataStore.data.map { it[UPDATE_LAST_CHECK_AT] ?: 0L }
    val updateLatestVersion: Flow<String> = dataStore.data.map { it[UPDATE_LATEST_VERSION] ?: "" }
    val updateLastError: Flow<String> = dataStore.data.map { it[UPDATE_LAST_ERROR] ?: "" }
    val updateCheckIntervalHours: Flow<Int> = dataStore.data.map { it[UPDATE_CHECK_INTERVAL_HOURS] ?: 24 }
    val updatePostponeUntil: Flow<Long> = dataStore.data.map { it[UPDATE_POSTPONE_UNTIL] ?: 0L }
    val updatePostponeVersion: Flow<String> = dataStore.data.map { it[UPDATE_POSTPONE_VERSION] ?: "" }
    val updateDialogLastShownVersion: Flow<String> = dataStore.data.map { it[UPDATE_DIALOG_LAST_SHOWN_VERSION] ?: "" }
    val updateDialogLastShownAt: Flow<Long> = dataStore.data.map { it[UPDATE_DIALOG_LAST_SHOWN_AT] ?: 0L }
    val updateDialogLastActionVersion: Flow<String> = dataStore.data.map { it[UPDATE_DIALOG_LAST_ACTION_VERSION] ?: "" }
    val updateDialogLastAction: Flow<String> = dataStore.data.map { it[UPDATE_DIALOG_LAST_ACTION] ?: "" }
    val updateDialogLastActionAt: Flow<Long> = dataStore.data.map { it[UPDATE_DIALOG_LAST_ACTION_AT] ?: 0L }

    suspend fun saveThemeMode(mode: String) {
        dataStore.edit { prefs ->
            prefs[THEME_MODE] = mode
        }
    }

    suspend fun saveDynamicColor(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[IS_DYNAMIC_COLOR] = enabled
        }
    }

    suspend fun saveThemePalette(palette: String) {
        dataStore.edit { prefs ->
            prefs[THEME_PALETTE] = palette
        }
    }

    suspend fun saveActiveClientIds(clientIds: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] = clientIds
        }
    }

    suspend fun saveClientIdCheckResults(resultsJson: String) {
        dataStore.edit { prefs ->
            prefs[CLIENT_ID_CHECK_RESULTS] = resultsJson
        }
    }

    suspend fun saveUpdateState(lastCheckAt: Long, latestVersion: String, error: String) {
        dataStore.edit { prefs ->
            prefs[UPDATE_LAST_CHECK_AT] = lastCheckAt
            prefs[UPDATE_LATEST_VERSION] = latestVersion
            prefs[UPDATE_LAST_ERROR] = error
        }
    }

    suspend fun saveUpdateCheckIntervalHours(hours: Int) {
        dataStore.edit { prefs ->
            prefs[UPDATE_CHECK_INTERVAL_HOURS] = hours
        }
    }

    suspend fun saveUpdatePostpone(version: String, until: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_POSTPONE_VERSION] = version
            prefs[UPDATE_POSTPONE_UNTIL] = until
        }
    }

    suspend fun saveUpdateDialogShown(version: String, shownAt: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_DIALOG_LAST_SHOWN_VERSION] = version
            prefs[UPDATE_DIALOG_LAST_SHOWN_AT] = shownAt
        }
    }

    suspend fun saveUpdateDialogAction(version: String, action: String, actedAt: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_DIALOG_LAST_ACTION_VERSION] = version
            prefs[UPDATE_DIALOG_LAST_ACTION] = action
            prefs[UPDATE_DIALOG_LAST_ACTION_AT] = actedAt
        }
    }

    suspend fun saveActiveProfile(profile: Int) {
        dataStore.edit { prefs ->
            prefs[ACTIVE_PROFILE] = profile
        }
    }

    suspend fun saveShowSystemApps(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[SHOW_SYSTEM_APPS] = enabled
        }
    }

    suspend fun saveLoggingEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[LOGGING_ENABLED] = enabled
        }
    }

    suspend fun saveWdttLink(link: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WDTT_LINK, profile)] = link
        }
    }

    suspend fun saveWdttLinkMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = enabled
        }
    }

    suspend fun saveConnectionProfile(profile: ConnectionProfile) {
        dataStore.edit { prefs ->
            val activeSettingsProfile = prefs[ACTIVE_PROFILE] ?: 0
            val profilesKey = getProfileKey(CONNECTION_PROFILES_ENCRYPTED, activeSettingsProfile)
            val current = ConnectionProfile.decodeList(secureStore.decrypt(prefs[profilesKey]).orEmpty())
            val updated = current.filterNot { it.id == profile.id || it.sourceLink == profile.sourceLink } + profile
            prefs[profilesKey] = secureStore.encrypt(ConnectionProfile.encodeList(updated))
            prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, activeSettingsProfile)] = profile.id
            prefs[getProfileKey(WDTT_LINK_MODE, activeSettingsProfile)] = true
        }
    }

    suspend fun updateConnectionProfileWorkers(id: String, workers: Int) {
        dataStore.edit { prefs ->
            val activeSettingsProfile = prefs[ACTIVE_PROFILE] ?: 0
            val profilesKey = getProfileKey(CONNECTION_PROFILES_ENCRYPTED, activeSettingsProfile)
            val current = ConnectionProfile.decodeList(secureStore.decrypt(prefs[profilesKey]).orEmpty())
            val index = current.indexOfFirst { it.id == id }
            if (index < 0) return@edit

            val updated = current.toMutableList()
            updated[index] = current[index].copy(workers = normalizeConnectionProfileWorkers(workers))
            prefs[profilesKey] = secureStore.encrypt(ConnectionProfile.encodeList(updated))
        }
    }

    suspend fun selectConnectionProfile(id: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, profile)] = id
            prefs[getProfileKey(WDTT_LINK_MODE, profile)] = true
        }
    }

    suspend fun removeConnectionProfile(id: String) {
        dataStore.edit { prefs ->
            val activeSettingsProfile = prefs[ACTIVE_PROFILE] ?: 0
            val profilesKey = getProfileKey(CONNECTION_PROFILES_ENCRYPTED, activeSettingsProfile)
            val updated = ConnectionProfile.decodeList(secureStore.decrypt(prefs[profilesKey]).orEmpty())
                .filterNot { it.id == id }
            if (updated.isEmpty()) {
                prefs.remove(profilesKey)
                prefs.remove(getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, activeSettingsProfile))
            } else {
                prefs[profilesKey] = secureStore.encrypt(ConnectionProfile.encodeList(updated))
                val selected = prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, activeSettingsProfile)]
                if (selected == id) {
                    prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, activeSettingsProfile)] = updated.first().id
                }
            }
        }
    }

    suspend fun activeConnectionProfile(): ConnectionProfile? {
        val prefs = dataStore.data.first()
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        if (prefs[getProfileKey(WDTT_LINK_MODE, profile)] != true) return null
        val profiles = ConnectionProfile.decodeList(
            secureStore.decrypt(prefs[getProfileKey(CONNECTION_PROFILES_ENCRYPTED, profile)]).orEmpty()
        )
        val selectedId = prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, profile)]
        return profiles.firstOrNull { it.id == selectedId } ?: profiles.firstOrNull()
    }

    suspend fun save(
        peer: String,
        vkHashes: String,
        secondaryVkHash: String,
        workersPerHash: Int,
        listenPort: Int
    ) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(PEER, profile)] = peer
            prefs[getProfileKey(VK_HASHES, profile)] = vkHashes
            prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = secondaryVkHash
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = workersPerHash
            prefs[getProfileKey(LISTEN_PORT, profile)] = listenPort
        }
    }

    suspend fun saveManualPortsEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = enabled
        }
    }

    suspend fun savePorts(serverDtlsPort: Int, serverWgPort: Int, listenPort: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(SERVER_DTLS_PORT, profile)] = serverDtlsPort
            prefs[getProfileKey(SERVER_WG_PORT, profile)] = serverWgPort
            prefs[getProfileKey(LISTEN_PORT, profile)] = listenPort
        }
    }

    suspend fun saveExcludedApps(packages: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(EXCLUDED_APPS, profile)] = packages
            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }
    suspend fun saveConnectionPassword(password: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs.putSecret(CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD, password, profile)
        }
    }

    suspend fun saveVkAuthMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(VK_AUTH_MODE, profile)] = if (mode == "legacy") "legacy" else "vkcalls"
        }
    }

    suspend fun saveObfsMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(OBFS_MODE, profile)] = mode
        }
    }

    suspend fun saveCaptchaMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_MODE, profile)] = mode
        }
    }

    suspend fun saveCaptchaSolveMethod(method: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = method
        }
    }

    suspend fun saveWbvCaptchaSolveMethod(method: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] = method
            if (prefs[getProfileKey(CAPTCHA_MODE, profile)] == "wv") {
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = method
            }
        }
    }

    
    suspend fun saveIsWhitelist(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(IS_WHITELIST, profile)] = enabled
            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    
    suspend fun saveExceptionsMode(packages: String, isWhitelist: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(EXCLUDED_APPS, profile)] = packages
            prefs[getProfileKey(IS_WHITELIST, profile)] = isWhitelist
            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    private suspend fun migrateLegacyWdttLink() {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val profilesKey = getProfileKey(CONNECTION_PROFILES_ENCRYPTED, profile)
            if (!prefs[profilesKey].isNullOrBlank()) return@edit
            val legacyLink = prefs[getProfileKey(WDTT_LINK, profile)] ?: return@edit
            val imported = runCatching { ConnectionProfileParser.parse(legacyLink) }.getOrNull() ?: return@edit
            prefs[profilesKey] = secureStore.encrypt(ConnectionProfile.encodeList(listOf(imported)))
            prefs[getProfileKey(ACTIVE_CONNECTION_PROFILE_ID, profile)] = imported.id
        }
    }

    private suspend fun migrateSecretsToKeystore() {
        dataStore.edit { prefs ->
            for (profile in 0..2) {
                prefs.migrateSecret(getProfileKey(CONNECTION_PASSWORD_ENCRYPTED, profile), getProfileKey(CONNECTION_PASSWORD, profile))
            }
        }
    }

    private suspend fun purgeLegacyDeploySettings() {
        val names = listOf(
            "deploy_ip",
            "deploy_login",
            "deploy_password",
            "deploy_password_encrypted",
            "deploy_ssh_port",
            "deploy_dns1",
            "deploy_dns2",
            "deploy_main_password",
            "deploy_main_password_encrypted",
            "deploy_admin_id",
            "deploy_admin_id_encrypted",
            "deploy_bot_token",
            "deploy_bot_token_encrypted",
        )
        dataStore.edit { prefs ->
            for (profile in 0..2) {
                val suffix = if (profile == 0) "" else "_$profile"
                for (name in names) {
                    prefs.remove(stringPreferencesKey(name + suffix))
                }
            }
        }
    }

    private suspend fun purgeRemovedTunnelSettings() {
        val stringNames = listOf("protocol", "sni", "user_agent", "proxy_mode", "proxy_host")
        val booleanNames = listOf("no_dns", "detailed_logs")
        dataStore.edit { prefs ->
            for (profile in 0..2) {
                val suffix = if (profile == 0) "" else "_$profile"
                stringNames.forEach { prefs.remove(stringPreferencesKey(it + suffix)) }
                booleanNames.forEach { prefs.remove(booleanPreferencesKey(it + suffix)) }
                prefs.remove(intPreferencesKey("proxy_port$suffix"))
            }
        }
    }

    suspend fun migrateLegacyWhitelistMode() {
        val currentPrefs = dataStore.data.first()
        if (currentPrefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] == true) return

        val hasLegacyWhitelist = (0..2).any { profile ->
            currentPrefs[getProfileKey(IS_WHITELIST, profile)] == true
        }
        val installedApps = if (hasLegacyWhitelist) installedSplitTunnelPackages() else emptySet()
        dataStore.edit { prefs ->
            if (prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] == true) return@edit

            for (profile in 0..2) {
                val whitelistKey = getProfileKey(IS_WHITELIST, profile)
                val appsKey = getProfileKey(EXCLUDED_APPS, profile)
                if (prefs[whitelistKey] == true) {
                    val legacyExcluded = prefs[appsKey]
                        ?.split(",")
                        ?.filter { it.isNotEmpty() }
                        ?.toSet()
                        ?: emptySet()
                    prefs[appsKey] = (installedApps - legacyExcluded).sorted().joinToString(",")
                }
            }

            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    private fun installedSplitTunnelPackages(): Set<String> {
        return runCatching {
            appContext.packageManager
                .getInstalledApplications(PackageManager.GET_META_DATA)
                .map { it.packageName }
                .filter {
                    it != appContext.packageName &&
                        !it.contains("vkontakte") &&
                        !it.contains("vk.calls")
                }
                .toSet()
        }.getOrDefault(emptySet())
    }

    private fun readSecret(
        prefs: Preferences,
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        profile: Int
    ): String {
        val profEncryptedKey = getProfileKey(encryptedKey, profile)
        val profLegacyKey = getProfileKey(legacyKey, profile)
        return secureStore.decrypt(prefs[profEncryptedKey]) ?: prefs[profLegacyKey] ?: ""
    }

    private fun MutablePreferences.putSecret(
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        value: String,
        profile: Int
    ) {
        val profEncryptedKey = getProfileKey(encryptedKey, profile)
        val profLegacyKey = getProfileKey(legacyKey, profile)
        if (value.isBlank()) {
            remove(profEncryptedKey)
            remove(profLegacyKey)
        } else {
            this[profEncryptedKey] = secureStore.encrypt(value)
            remove(profLegacyKey)
        }
    }

    private fun MutablePreferences.migrateSecret(
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>
    ) {
        val legacyValue = this[legacyKey]
        val encryptedValue = this[encryptedKey]
        if (!encryptedValue.isNullOrBlank()) {
            remove(legacyKey)
            return
        }
        if (!legacyValue.isNullOrBlank()) {
            runCatching {
                this[encryptedKey] = secureStore.encrypt(legacyValue)
                remove(legacyKey)
            }
        }
    }
}
