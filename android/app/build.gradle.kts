plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.jiter.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.jiter.app"
        minSdk = 29
        targetSdk = 35
        versionCode = 6
        versionName = "0.7.1-stage6-redesign"

        val defaultControlUrl = (project.findProperty("jiterControlPlaneUrl") as String?)
            ?.trim()
            ?.replace("\"", "")
            ?: "https://jiter-control-plane-two.vercel.app"
        val defaultControlKey = (project.findProperty("jiterControlPlaneAppKey") as String?)
            ?.trim()
            ?.replace("\"", "")
            ?: ""
        buildConfigField("String", "DEFAULT_CONTROL_PLANE_URL", "\"$defaultControlUrl\"")
        buildConfigField("String", "DEFAULT_CONTROL_PLANE_APP_KEY", "\"$defaultControlKey\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "META-INF/DEPENDENCIES",
            )
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("com.google.android.material:material:1.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation("junit:junit:4.13.2")
}
