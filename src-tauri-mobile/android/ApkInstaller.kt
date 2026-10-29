package com.sealbox.mobile

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.annotation.Keep
import androidx.core.content.FileProvider
import java.io.File

/**
 * Opens the system package installer for an already downloaded APK.
 *
 * Called from the JavaBridge thread via JNI. FileProvider must run on the app
 * class loader, and startActivity must run on the UI thread.
 */
@Keep
object ApkInstaller {
    @JvmStatic
    fun open(context: Context, path: String) {
        val file = File(path)
        if (!file.isFile) throw IllegalArgumentException("安装包不存在")
        val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val activity = context as? Activity
        if (activity != null) {
            activity.runOnUiThread { activity.startActivity(intent) }
        } else {
            context.applicationContext.startActivity(intent)
        }
    }
}
