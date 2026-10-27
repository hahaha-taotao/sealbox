package com.sealbox.mobile

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.os.SystemClock
import androidx.activity.result.ActivityResult
import androidx.appcompat.app.AppCompatActivity
import androidx.annotation.Keep
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

@InvokeArg
class OpenDocumentArgs { var mimeTypes: List<String> = listOf("*/*") }

@InvokeArg
class SaveDocumentArgs {
    var suggestedName: String = "sealbox-backup.json"
    var mime: String = "application/octet-stream"
}

private const val GRANT_TTL_MS = 10 * 60 * 1000L

private class ActivityGrant {
    @Volatile var active = true
}

/** One CREATE_DOCUMENT capability. `issuedAt` is elapsedRealtime at registration. */
private class DocumentGrant(private val activity: ActivityGrant) {
    val issuedAt: Long = SystemClock.elapsedRealtime()

    val active: Boolean
        get() = activity.active

    fun expired(now: Long = SystemClock.elapsedRealtime()): Boolean {
        val age = now - issuedAt
        return age < 0L || age >= GRANT_TTL_MS
    }

    fun ownedBy(activity: ActivityGrant) = this.activity === activity
}

/** Only picker metadata crosses the plugin bridge. File bytes use static JNI helpers below. */
@Keep
@TauriPlugin
class DocumentsPlugin(private val activity: Activity) : Plugin(activity) {
    private var pending: Invoke? = null
    private var creating = false
    private val grantOwner = ActivityGrant()
    @Volatile private var destroyed = false

    @Command
    fun pickOpen(invoke: Invoke) {
        try {
            val types = invoke.parseArgs(OpenDocumentArgs::class.java).mimeTypes
            require(types.isNotEmpty() && types.all { validMime(it) })
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = if (types.size == 1) types[0] else "*/*"
                if (types.size > 1) putExtra(Intent.EXTRA_MIME_TYPES, types.toTypedArray())
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            launch(invoke, intent, false)
        } catch (_: Exception) {
            invoke.reject("SAF open picker could not start")
        }
    }

    @Command
    fun pickSave(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SaveDocumentArgs::class.java)
            require(validMime(args.mime) && args.suggestedName.isNotBlank())
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = args.mime
                putExtra(Intent.EXTRA_TITLE, args.suggestedName)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }
            launch(invoke, intent, true)
        } catch (_: Exception) {
            invoke.reject("SAF save picker could not start")
        }
    }

    private fun launch(invoke: Invoke, intent: Intent, create: Boolean) {
        activity.runOnUiThread {
            if (destroyed || activity.isFinishing || activity.isDestroyed) {
                invoke.reject("SAF activity is unavailable")
            } else if (pending != null) {
                invoke.reject("Another SAF picker is already active")
            } else {
                pending = invoke
                creating = create
                try {
                    startActivityForResult(invoke, intent, "documentResult")
                } catch (_: Exception) {
                    pending = null
                    creating = false
                    invoke.reject("SAF provider is unavailable")
                }
            }
        }
    }

    @ActivityCallback
    fun documentResult(invoke: Invoke, result: ActivityResult) {
        if (destroyed || pending !== invoke) return
        val create = creating
        if (result.resultCode == Activity.RESULT_CANCELED) {
            pending = null
            creating = false
            invoke.resolve(JSObject().put("document", org.json.JSONObject.NULL))
            return
        }
        val uri = result.data?.data
        if (result.resultCode != Activity.RESULT_OK || uri == null || uri.scheme != "content") {
            pending = null
            creating = false
            invoke.reject("SAF provider returned an invalid document")
            return
        }
        // Retain pending during metadata I/O so destroy/rotation can reject it exactly once.
        // Providers can block; keep all ContentResolver queries off the activity thread.
        Thread {
            try {
                val name = activity.contentResolver.query(
                    uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null
                )?.use { cursor ->
                    if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getString(0) else null
                }
                activity.runOnUiThread {
                    if (!destroyed && pending === invoke) {
                        pending = null
                        creating = false
                        if (create) {
                            val uriText = uri.toString()
                            val grant = DocumentGrant(grantOwner)
                            createdDocuments[uriText] = grant
                            if (grant.expired() || !grant.active) {
                                createdDocuments.remove(uriText)
                                invoke.reject(
                                    if (grant.expired()) "SAF document grant expired"
                                    else "SAF activity was destroyed"
                                )
                                return@runOnUiThread
                            }
                        }
                        val document = JSObject().put("uri", uri.toString())
                            .put("name", name ?: "document")
                        invoke.resolve(JSObject().put("document", document))
                    }
                }
            } catch (_: Exception) {
                activity.runOnUiThread {
                    if (!destroyed && pending === invoke) {
                        pending = null
                        creating = false
                        invoke.reject(if (create) {
                            "SAF metadata failed; an empty document may need manual cleanup"
                        } else "SAF document metadata could not be read")
                    }
                }
            }
        }.start()
    }

    override fun onDestroy(activity: AppCompatActivity) {
        destroyed = true
        grantOwner.active = false
        createdDocuments.entries.removeIf { it.value.ownedBy(grantOwner) }
        pending?.reject("SAF activity was destroyed; retry the picker")
        pending = null
        creating = false
        super.onDestroy(activity)
    }

    companion object {
        private const val MAX_BYTES = 128 * 1024 * 1024
        private val createdDocuments = ConcurrentHashMap<String, DocumentGrant>()
        private fun validMime(mime: String) = mime.length <= 255 &&
            Regex("^[A-Za-z0-9!#$&^_.+*\\-]+/[A-Za-z0-9!#$&^_.+*\\-]+$").matches(mime)

        private fun contentUri(value: String): Uri {
            val uri = Uri.parse(value)
            require(uri.scheme == "content" && !uri.authority.isNullOrBlank()) {
                "Only opaque content URIs are accepted"
            }
            return uri
        }

        private class WipingOutput : ByteArrayOutputStream() {
            fun wipe() { buf.fill(0); reset() }
        }

        /** Rust blocking worker only, deliberately not an @Command. */
        @JvmStatic
        fun readBytes(context: Context, value: String, maxBytes: Int): ByteArray {
            require(maxBytes in 1..MAX_BYTES) { "Invalid SAF read limit" }
            val uri = contentUri(value)
            val output = WipingOutput()
            val buffer = ByteArray(64 * 1024)
            try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    var total = 0
                    while (true) {
                        val count = input.read(buffer, 0, minOf(buffer.size, maxBytes - total + 1))
                        if (count < 0) break
                        if (count == 0) throw IOException("SAF provider made no read progress")
                        if (count > maxBytes - total) throw IOException("SAF document exceeds read limit")
                        output.write(buffer, 0, count)
                        total += count
                    }
                } ?: throw IOException("SAF document is not readable")
                return output.toByteArray()
            } catch (_: Exception) {
                throw IOException("SAF read failed or document exceeds the caller's byte limit")
            } finally {
                buffer.fill(0)
                output.wipe()
            }
        }

        /** Single-use CREATE_DOCUMENT grant only. Providers may leave a partial file on failure. */
        @JvmStatic
        fun writeNewBytes(context: Context, value: String, bytes: ByteArray) {
            try {
                val uri = contentUri(value)
                require(bytes.size <= MAX_BYTES) { "SAF output exceeds byte limit" }
                val grant = createdDocuments[value]
                    ?: throw IOException("SAF destination is not a fresh created document")
                if (grant.expired() || !grant.active) {
                    createdDocuments.remove(value)
                    throw IOException(
                        if (grant.expired()) "SAF document grant expired"
                        else "SAF document belongs to a destroyed activity"
                    )
                }
                if (createdDocuments.remove(value) == null) {
                    throw IOException("SAF destination is not a fresh created document")
                }
                val expected = MessageDigest.getInstance("SHA-256").digest(bytes)
                try {
                    if (grant.expired()) {
                        createdDocuments.remove(value)
                        throw IOException("SAF document grant expired")
                    }
                    check(grant.active) { "SAF document belongs to a destroyed activity" }
                    context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                        var offset = 0
                        while (offset < bytes.size) {
                            if (grant.expired()) {
                                createdDocuments.remove(value)
                                throw IOException("SAF document grant expired")
                            }
                            check(grant.active) { "SAF activity was destroyed during write" }
                            val count = minOf(64 * 1024, bytes.size - offset)
                            output.write(bytes, offset, count)
                            offset += count
                        }
                        output.flush()
                    } ?: throw IOException("SAF destination is not writable")
                    val digest = MessageDigest.getInstance("SHA-256")
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    try {
                        context.contentResolver.openInputStream(uri)?.use { input ->
                            while (true) {
                                if (grant.expired()) {
                                    createdDocuments.remove(value)
                                    throw IOException("SAF document grant expired")
                                }
                                check(grant.active) { "SAF document grant belongs to a destroyed activity" }
                                val count = input.read(buffer)
                                if (count < 0) break
                                if (count == 0) throw IOException("SAF provider made no read progress")
                                total += count
                                if (total > bytes.size.toLong()) throw IOException("SAF length mismatch")
                                digest.update(buffer, 0, count)
                            }
                        } ?: throw IOException("SAF verification stream unavailable")
                        if (grant.expired()) {
                            createdDocuments.remove(value)
                            throw IOException("SAF document grant expired")
                        }
                        check(grant.active && total == bytes.size.toLong() && MessageDigest.isEqual(expected, digest.digest())) {
                            "SAF verification mismatch"
                        }
                    } finally {
                        buffer.fill(0)
                    }
                } catch (_: Exception) {
                    throw IOException("SAF write or read-back verification failed; provider is not atomic, manually remove the possibly partial document")
                } finally {
                    expected.fill(0)
                }
            } finally {
                bytes.fill(0)
            }
        }
    }
}
