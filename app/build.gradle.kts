import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val defaultVersionCode = 200
val defaultVersionName = "2.0.0"
val releaseVersionCode = providers.gradleProperty("releaseVersionCode").orNull?.let { rawValue ->
    val parsedValue = rawValue.toLongOrNull()
        ?: throw GradleException("releaseVersionCode must be a decimal integer, got: $rawValue")
    if (parsedValue !in 1..2_100_000_000) {
        throw GradleException("releaseVersionCode must be between 1 and 2100000000, got: $rawValue")
    }
    parsedValue.toInt()
} ?: defaultVersionCode
val releaseVersionName = providers.gradleProperty("releaseVersionName").orNull?.let { rawValue ->
    val normalizedValue = rawValue.trim()
    if (!Regex("[0-9]+(?:\\.[0-9]+)*").matches(normalizedValue)) {
        throw GradleException(
            "releaseVersionName must contain dot-separated decimal components, got: $rawValue"
        )
    }
    normalizedValue
} ?: defaultVersionName

val requireReleaseSigning = providers.gradleProperty("requireReleaseSigning")
    .orNull
    ?.equals("true", ignoreCase = true)
    ?: false

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localPropertiesFile.inputStream().use { input -> localProperties.load(input) }
}

fun signingValue(name: String): String? =
    providers.environmentVariable(name).orNull?.takeIf { it.isNotEmpty() }
        ?: localProperties.getProperty(name)?.takeIf { it.isNotEmpty() }

val releaseKeystorePath = signingValue("KEYSTORE_FILE")
val releaseKeystorePassword = signingValue("KEYSTORE_PASSWORD")
val releaseKeyAlias = signingValue("KEY_ALIAS")
val releaseKeyPassword = signingValue("KEY_PASSWORD")
val releaseKeystoreFile = releaseKeystorePath?.let { configuredPath ->
    // Keep compatibility with the historical ../release.keystore value, which
    // referred to release.keystore in the repository root.
    val rootRelativePath = configuredPath.removePrefix("../").removePrefix("..\\")
    rootProject.file(rootRelativePath)
}
val hasReleaseSigning = releaseKeystoreFile?.isFile == true &&
    releaseKeystorePassword != null &&
    releaseKeyAlias != null &&
    releaseKeyPassword != null

if (requireReleaseSigning && !hasReleaseSigning) {
    throw GradleException(
        "Release signing is required, but KEYSTORE_FILE, KEYSTORE_PASSWORD, " +
            "KEY_ALIAS or KEY_PASSWORD is missing/invalid"
    )
}

android {
    namespace = "com.wdtt.client"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.wdtt.client"
        minSdk = 28
        targetSdk = 35
        versionCode = releaseVersionCode
        versionName = releaseVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = releaseKeystoreFile
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
                println("Signing config applied: ${releaseKeystoreFile?.absolutePath}")
            } else {
                println("WARNING: Release signing is not configured; the release APK will be unsigned")
                println("Looked for: ${releaseKeystoreFile?.absolutePath ?: releaseKeystorePath}")
            }
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/DEPENDENCIES"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.setSrcDirs(listOf("src/main/jniLibs"))
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("com.wireguard.android:tunnel:1.0.20230706")
}
