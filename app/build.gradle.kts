plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.mosip.authclient"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "io.mosip.authclient"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(libs.activity.ktx)
    implementation(libs.appcompat)
    implementation(libs.constraintlayout)
    implementation(libs.material)

    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("org.bitbucket.b_c:jose4j:0.9.6")

    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation(libs.junit)
    androidTestImplementation(libs.espresso.core)
    androidTestImplementation(libs.ext.junit)
}