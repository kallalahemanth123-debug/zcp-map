plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "dev.zcpmap.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.zcpmap.app"
        minSdk = 33          // Keystore Ed25519 (KeyMint 2), NEARBY_WIFI_DEVICES, UWB on all shipping devices
        targetSdk = 36
        versionCode = 3
        versionName = "2.0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        // Committed on purpose: every machine (and every CI run) signs debug APKs with this same key,
        // so a newer debug APK installs over an older one instead of failing with a signature mismatch.
        // It is a public test key. Release builds are left unsigned; sign them with your own key.
        getByName("debug") {
            storeFile = file("debug.keystore")
            storeType = "PKCS12"
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/{AL2.0,LGPL2.1}",
                "META-INF/BCKEY.DSA", "META-INF/BCKEY.SF",
            )
        }
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        checkReleaseBuilds = true
    }
}

dependencies {
    implementation(project(":core:protocol"))
    implementation(project(":core:security"))
    implementation(project(":core:mesh"))
    implementation(project(":core:agent"))
    implementation(project(":core:keystore"))
    implementation(project(":core:transport"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.play.services.nearby)
    implementation(libs.androidx.fragment)
    implementation(libs.litertlm.android)
    debugImplementation(libs.androidx.compose.ui.tooling)

    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
