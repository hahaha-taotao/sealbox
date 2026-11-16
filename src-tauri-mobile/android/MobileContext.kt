package com.sealbox.mobile

import android.app.Activity
import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.webkit.WebView
import androidx.annotation.Keep
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Plugin

/**
 * Nudges the Rust side to adopt the Android application context.
 *
 * These hooks must NOT publish into `ndk-context` themselves. tao 0.37 already calls
 * `ndk_context::initialize_android_context` from `Activity.onCreate`, and ndk-context 0.1.1
 * asserts on a second init — that abort was the 0.20.3+ "opens then dies" crash. Rust only
 * adopts whatever tao already published; these Kotlin paths just retry the adopt early and often:
 *  - [ContextBootstrapProvider] runs before `Application.onCreate` (usually too early to adopt,
 *    but harmless and keeps the manifest hook in place).
 *  - [MobileContextPlugin.load] runs while the webview is created.
 *  - [Application.ActivityLifecycleCallbacks] fires for the first activity after tao has published.
 *
 * None of them may throw: an exception escaping `load` fails Tauri's plugin registration, and one
 * escaping a provider or lifecycle callback kills the process. A missing context only degrades
 * three features, so every failure is logged and swallowed.
 */
@Keep
class ContextBootstrapProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let { NdkContext.initializeQuietly(it) }
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}

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

    /**
     * Loaded lazily rather than in an `init` block.
     *
     * `init` runs on first touch and a failure there poisons the class for the rest of the process:
     * every later call throws `ExceptionInInitializerError`. Loading inside a `try` keeps a missing
     * or mismatched library a logged, retryable problem instead.
     */
    private var loaded = false

    @JvmStatic
    external fun initialize(context: Context)

    /** Never throws. Safe to call any number of times. */
    fun initializeQuietly(context: Context) {
        if (!ensureLoaded()) return
        try {
            initialize(context.applicationContext)
        } catch (error: Throwable) {
            report("initialize failed", error)
        }
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
     * Extra chance for a process whose provider and plugin both failed.
     *
     * Registered once; a second call is a no-op.
     */
    fun watchActivities(application: Application) {
        if (watching) return
        watching = true
        try {
            application.registerActivityLifecycleCallbacks(
                object : Application.ActivityLifecycleCallbacks {
                    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                        initializeQuietly(activity.applicationContext)
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
