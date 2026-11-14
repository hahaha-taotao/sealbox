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
 * SAF and the update installer would panic on `ndk_context::android_context()`. `load` runs while
 * the webview is created, before any command can be invoked.
 *
 * An exception escaping `load` fails Tauri's plugin registration for this plugin, and the context is
 * then never published for the whole process — which is exactly the bug this class exists to avoid.
 * So `load` itself cannot throw, and the framework-driven lifecycle callback is registered as a
 * second chance in case the plugin is never loaded at all.
 */
@Keep
@TauriPlugin
class MobileContextPlugin(private val activity: Activity) : Plugin(activity) {
    override fun load(webView: WebView) {
        NdkContext.publish(activity)
    }
}

/** Android-only bridge; the Rust symbol is `Java_com_sealbox_mobile_NdkContext_initialize`. */
@Keep
object NdkContext {
    private const val TAG = "Sealbox"

    /**
     * Loaded lazily by [publish] rather than in an `init` block.
     *
     * `init` runs on first touch of the object, and a failure there poisons the class for the rest
     * of the process: every later call throws `ExceptionInInitializerError`. Loading inside a
     * `try` keeps a missing or mismatched library a logged, retryable problem instead.
     */
    private var loaded = false

    @JvmStatic
    external fun initialize(context: Context)

    /**
     * Publishes `activity`'s application context. Never throws.
     *
     * Both the `initialize` call and the lifecycle registration are best effort: a failure here
     * degrades three features and must not take down the plugin or the app.
     */
    fun publish(activity: Activity) {
        if (!ensureLoaded()) return
        try {
            initialize(activity.applicationContext)
        } catch (error: Throwable) {
            report("initialize failed", error)
        }
        watchActivities(activity)
    }

    private fun ensureLoaded(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("sealbox_mobile_lib")
            loaded = true
            true
        } catch (error: Throwable) {
            report("loadLibrary failed", error)
            false
        }
    }

    /**
     * Second chance, independent of Tauri's plugin registration.
     *
     * `onActivityCreated` is driven by the framework, so it fires even when `load` never does. It
     * runs slightly later than `load`, which is why `load` still publishes first when it can.
     * Registered once; a second call is a no-op.
     */
    private fun watchActivities(activity: Activity) {
        if (watching) return
        watching = true
        try {
            activity.application.registerActivityLifecycleCallbacks(
                object : Application.ActivityLifecycleCallbacks {
                    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                        if (!ensureLoaded()) return
                        try {
                            initialize(activity.applicationContext)
                        } catch (error: Throwable) {
                            report("lifecycle initialize failed", error)
                        }
                    }

                    override fun onActivityStarted(activity: Activity) = Unit
                    override fun onActivityResumed(activity: Activity) = Unit
                    override fun onActivityPaused(activity: Activity) = Unit
                    override fun onActivityStopped(activity: Activity) = Unit
                    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
                    override fun onActivityDestroyed(activity: Activity) = Unit
                },
            )
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
