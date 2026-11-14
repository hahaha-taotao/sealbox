package com.sealbox.mobile

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.webkit.WebView
import androidx.annotation.Keep
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Plugin

/**
 * Publishes the Android application context to the Rust JNI helpers.
 *
 * Tauri 2.11 / tao 0.35 no longer initialize `ndk-context` (tao 0.36 restores it), so clipboard,
 * SAF and the update installer would panic on `ndk_context::android_context()`.
 *
 * Two independent paths, because neither is guaranteed on its own:
 *  - [load] is the earliest one, and the only one that runs before the webview can invoke a
 *    command. It is driven by Tauri's plugin registration, which skips or fails it if the
 *    generated project differs from what the Rust side expects.
 *  - [Application.ActivityLifecycleCallbacks.onActivityCreated] fires from the framework itself, so
 *    it does not depend on Tauri at all. It runs slightly later, which is why [load] is tried
 *    first.
 *
 * Neither path may throw: an exception escaping `load` fails plugin registration, and one escaping
 * a lifecycle callback kills the process. A missing context only degrades three features, so every
 * failure here is logged and swallowed.
 */
@Keep
@TauriPlugin
class MobileContextPlugin(private val activity: Activity) : Plugin(activity) {
    override fun load(webView: WebView) {
        NdkContext.initializeQuietly(activity.applicationContext)
        NdkContext.watchActivities(activity.application)
    }
}

/** Android-only bridge; the Rust symbol is `Java_com_sealbox_mobile_NdkContext_initialize`. */
@Keep
object NdkContext {
    private const val TAG = "Sealbox"

    init {
        try {
            System.loadLibrary("sealbox_mobile_lib")
        } catch (error: Throwable) {
            // Reported, not thrown: a library that failed to load only breaks the three JNI
            // features, and letting this escape would abort class initialisation for the plugin.
            report("loadLibrary failed", error)
        }
    }

    @JvmStatic
    external fun initialize(context: Context)

    /** Never throws. Returns whether the context was published. */
    fun initializeQuietly(context: Context) {
        try {
            initialize(context.applicationContext)
        } catch (error: Throwable) {
            report("initialize failed", error)
        }
    }

    /**
     * Publishes on the first activity that reaches `onActivityCreated`.
     *
     * Registered once; a second call is a no-op. Only `onActivityCreated` is used, so rotation and
     * multi-activity apps are covered without keeping any reference of our own — the framework
     * disposes the callbacks with the application.
     */
    fun watchActivities(application: Application) {
        if (watching) return
        watching = true
        try {
            application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
                override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                    initializeQuietly(activity.applicationContext)
                }

                override fun onActivityStarted(activity: Activity) = Unit
                override fun onActivityResumed(activity: Activity) = Unit
                override fun onActivityPaused(activity: Activity) = Unit
                override fun onActivityStopped(activity: Activity) = Unit
                override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
                override fun onActivityDestroyed(activity: Activity) = Unit
            })
        } catch (error: Throwable) {
            report("registerActivityLifecycleCallbacks failed", error)
        }
    }

    @Volatile
    private var watching = false

    /** Logcat is the only channel that outlives a field report; stderr is often filtered. */
    private fun report(what: String, error: Throwable) {
        try {
            Log.e(TAG, "context bridge: $what: $error")
        } catch (_: Throwable) {
            // Nothing left to report to.
        }
    }
}
