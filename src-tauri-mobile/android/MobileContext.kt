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
 * Publishes the Android application context to the Rust JNI helpers.
 *
 * Tauri 2.11 / tao 0.35 no longer initialize `ndk-context` (tao 0.36 restores it), so clipboard,
 * SAF and the update installer would panic on `ndk_context::android_context()`.
 *
 * Three independent paths, tried in the order they become available:
 *  - [ContextBootstrapProvider] runs before `Application.onCreate` and is declared in the manifest.
 *    The framework instantiates it unconditionally, so this is the one path that cannot be skipped
 *    by anything the app or Tauri does later.
 *  - [MobileContextPlugin.load] runs while the webview is created, which is still before any
 *    command can be invoked.
 *  - [Application.ActivityLifecycleCallbacks] fires for the first activity after that.
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
