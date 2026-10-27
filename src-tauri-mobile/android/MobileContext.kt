package com.sealbox.mobile

import android.app.Activity
import android.content.Context
import android.webkit.WebView
import androidx.annotation.Keep
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Plugin

/**
 * Publishes the Android application context to the Rust JNI helpers.
 *
 * Tauri 2.11 / tao 0.35 no longer initialize `ndk-context` (tao 0.36 restores it), so clipboard,
 * SAF and the update installer would panic on `ndk_context::android_context()`. This runs while the
 * webview is created, before any command can be invoked.
 */
@Keep
@TauriPlugin
class MobileContextPlugin(private val activity: Activity) : Plugin(activity) {
    override fun load(webView: WebView) {
        NdkContext.initialize(activity.applicationContext)
    }
}

/** Android-only bridge; the Rust symbol is `Java_com_sealbox_mobile_NdkContext_initialize`. */
@Keep
object NdkContext {
    init {
        System.loadLibrary("sealbox_mobile_lib")
    }

    @JvmStatic
    external fun initialize(context: Context)
}
