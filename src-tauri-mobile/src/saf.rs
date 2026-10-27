//! Android Storage Access Framework boundary. Never turn a content URI into a path.
//! Register `saf::init()` in the mobile builder; do not expose byte helpers as commands.
use serde::Deserialize;
use tauri::{plugin::TauriPlugin, AppHandle, Runtime};

pub const MAX_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Deserialize)]
pub struct SelectedDocument {
    pub uri: String,
    pub name: String,
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("saf")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                use tauri::Manager;
                let handle = _api.register_android_plugin("com.sealbox.mobile", "DocumentsPlugin")?;
                _app.manage(android::Documents(handle));
            }
            Ok(())
        })
        .build()
}

/// Cancellation is `Ok(None)` and must not mutate the vault.
pub async fn pick_open<R: Runtime>(
    app: &AppHandle<R>,
    mime_types: &[&str],
) -> Result<Option<SelectedDocument>> {
    #[cfg(target_os = "android")]
    {
        let handle = android::handle(app)?;
        let payload = serde_json::json!({ "mimeTypes": mime_types });
        return tauri::async_runtime::spawn_blocking(move || {
            let response: android::PickerResponse = handle
                .run_mobile_plugin("pickOpen", payload)
                .map_err(|error| error.to_string())?;
            Ok(response.document)
        })
        .await
        .map_err(|_| "SAF picker worker failed".to_string())?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, mime_types);
        unsupported()
    }
}

pub async fn pick_save<R: Runtime>(
    app: &AppHandle<R>,
    suggested_name: &str,
    mime: &str,
) -> Result<Option<SelectedDocument>> {
    #[cfg(target_os = "android")]
    {
        let handle = android::handle(app)?;
        let payload = serde_json::json!({ "suggestedName": suggested_name, "mime": mime });
        return tauri::async_runtime::spawn_blocking(move || {
            let response: android::PickerResponse = handle
                .run_mobile_plugin("pickSave", payload)
                .map_err(|error| error.to_string())?;
            Ok(response.document)
        })
        .await
        .map_err(|_| "SAF picker worker failed".to_string())?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, suggested_name, mime);
        unsupported()
    }
}

/// Caller selects the bound (e.g. 128 MiB backup, 5 MiB CSV) before reading.
/// Returned bytes stay in native code; callers should zeroize them after consumption.
pub async fn read<R: Runtime>(app: &AppHandle<R>, uri: &str, max_bytes: usize) -> Result<Vec<u8>> {
    validate_uri(uri)?;
    if max_bytes == 0 || max_bytes > MAX_DOCUMENT_BYTES {
        return Err("Invalid SAF read limit (maximum 128 MiB)".into());
    }
    #[cfg(target_os = "android")]
    {
        android::handle(app)?;
        let uri = uri.to_owned();
        return tauri::async_runtime::spawn_blocking(move || android::read(&uri, max_bytes))
            .await
            .map_err(|_| "SAF read worker failed".to_string())?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        unsupported()
    }
}

/// Only a fresh `pick_save` URI may be consumed, once. Success means the closed
/// output has been read back and its exact length and SHA-256 verified by Android.
/// Failure may leave an empty/partial document: providers do not promise atomicity.
pub async fn write_new<R: Runtime>(app: &AppHandle<R>, uri: &str, bytes: Vec<u8>) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(bytes);
    validate_uri(uri)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("SAF output exceeds 128 MiB".into());
    }
    #[cfg(target_os = "android")]
    {
        android::handle(app)?;
        let uri = uri.to_owned();
        return tauri::async_runtime::spawn_blocking(move || android::write_new(&uri, &bytes))
            .await
            .map_err(|_| "SAF write worker failed; a partial document may need cleanup".to_string())?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        unsupported()
    }
}

fn validate_uri(uri: &str) -> Result<()> {
    // Validate the scheme only, without decoding/re-encoding opaque provider identifiers.
    if !uri.starts_with("content://") || uri["content://".len()..].is_empty() {
        return Err("SAF requires an opaque content:// URI, not a file path".into());
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn unsupported<T>() -> Result<T> {
    Err("Android SAF is unavailable on this platform".into())
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use jni::{objects::{JByteArray, JClass, JObject, JString}, JNIEnv};
    use tauri::{plugin::PluginHandle, Manager};

    pub struct Documents<R: Runtime>(pub PluginHandle<R>);

    #[derive(Deserialize)]
    pub struct PickerResponse {
        pub document: Option<SelectedDocument>,
    }

    pub fn handle<R: Runtime>(app: &AppHandle<R>) -> Result<PluginHandle<R>> {
        app.try_state::<Documents<R>>()
            .map(|state| state.0.clone())
            .ok_or_else(|| "SAF plugin is not registered".into())
    }

    fn with_env<T>(
        operation: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>, &JClass<'_>) -> Result<T>,
    ) -> Result<T> {
        let android = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(android.vm() as *mut _) }
            .map_err(|_| "SAF Java VM is unavailable".to_string())?;
        let mut env = vm.attach_current_thread()
            .map_err(|_| "SAF could not attach native worker".to_string())?;
        // Bound all JNI locals even when blocking pool threads are reused.
        env.with_local_frame(32, |env| -> jni::errors::Result<Result<T>> {
            let outcome = (|| {
                // NDK owns this global context; do not delete its reference.
                let context = unsafe { JObject::from_raw(android.context() as _) };
                let loader = env.call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
                    .map_err(|_| "SAF class loader is unavailable".to_string())?.l()
                    .map_err(|_| "SAF class loader is unavailable".to_string())?;
                let name = env.new_string("com.sealbox.mobile.DocumentsPlugin")
                    .map_err(|_| "SAF helper lookup failed".to_string())?;
                let class = env.call_method(loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[(&name).into()])
                    .map_err(|_| "SAF helper class is not installed".to_string())?.l()
                    .map_err(|_| "SAF helper class is not installed".to_string())?;
                operation(env, &context, &JClass::from(class))
            })();
            // Java exceptions must be cleared before returning a pooled native thread.
            if env.exception_check().unwrap_or(false) {
                let exception = env.exception_occurred()?;
                env.exception_clear()?;
                let message = env.call_method(exception, "getMessage", "()Ljava/lang/String;", &[])
                    .and_then(|value| value.l())
                    .ok()
                    .filter(|value| !value.is_null())
                    .and_then(|value| env.get_string(&JString::from(value)).ok().map(String::from));
                // Do not print exceptions, URIs, file data, or provider stack traces.
                if env.exception_check().unwrap_or(false) { env.exception_clear()?; }
                return Ok(Err(message.unwrap_or_else(|| "SAF native document operation failed".into())));
            }
            Ok(outcome)
        }).map_err(|_| "SAF JNI frame failed".to_string())?
    }

    pub fn read(uri: &str, max_bytes: usize) -> Result<Vec<u8>> {
        with_env(|env, context, class| {
            let uri = env.new_string(uri).map_err(|_| "SAF URI allocation failed".to_string())?;
            let array = env.call_static_method(class, "readBytes", "(Landroid/content/Context;Ljava/lang/String;I)[B",
                &[context.into(), (&uri).into(), (max_bytes as i32).into()])
                .map_err(|_| "SAF native read failed".to_string())?.l()
                .map_err(|_| "SAF native read returned no bytes".to_string())?;
            let array = JByteArray::from(array);
            let bytes = env.convert_byte_array(&array).map_err(|_| "SAF native byte transfer failed".to_string());
            let wiped = env.call_static_method("java/util/Arrays", "fill", "([BB)V", &[(&array).into(), 0i8.into()]);
            if wiped.is_err() { return Err("SAF native byte cleanup failed".into()); }
            bytes
        })
    }

    pub fn write_new(uri: &str, bytes: &[u8]) -> Result<()> {
        with_env(|env, context, class| {
            let uri = env
                .new_string(uri)
                .map_err(|_| "SAF URI allocation failed".to_string())?;
            let array = env
                .byte_array_from_slice(bytes)
                .map_err(|_| "SAF native byte allocation failed".to_string())?;
            let call = env.call_static_method(
                class,
                "writeNewBytes",
                "(Landroid/content/Context;Ljava/lang/String;[B)V",
                &[context.into(), (&uri).into(), (&array).into()],
            );
            // Failure can leave a pending exception before Kotlin starts, so its
            // finally never runs. Clear that exception before any wipe JNI call.
            let pending = !matches!(env.exception_check(), Ok(false));
            if call.is_err() || pending {
                clear_pending_exception(env);
                let _ = wipe_java_bytes(env, &array);
                return Err(
                    "SAF native write failed; a partial document may need cleanup".into(),
                );
            }
            if !wipe_java_bytes(env, &array) {
                return Err("SAF native byte cleanup failed".into());
            }
            Ok(())
        })
    }

    fn clear_pending_exception(env: &mut JNIEnv<'_>) {
        if !matches!(env.exception_check(), Ok(false)) {
            let _ = env.exception_clear();
        }
    }

    /// Zero this frame's Java `byte[]`. Returns false if both attempts failed.
    fn wipe_java_bytes(env: &mut JNIEnv<'_>, array: &JByteArray<'_>) -> bool {
        let wiped = env.call_static_method(
            "java/util/Arrays",
            "fill",
            "([BB)V",
            &[array.into(), 0i8.into()],
        );
        if wiped.is_ok() {
            return true;
        }
        clear_pending_exception(env);
        let retried = env.call_static_method(
            "java/util/Arrays",
            "fill",
            "([BB)V",
            &[array.into(), 0i8.into()],
        );
        if retried.is_err() {
            clear_pending_exception(env);
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_is_opaque_and_never_a_path() {
        assert!(validate_uri("content://provider/document/a%2Fb").is_ok());
        for value in ["", "/tmp/backup", "C:\\backup", "file:///backup", "https://example.org", "content://"] {
            assert!(validate_uri(value).is_err());
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn host_does_not_fake_document_io() {
        assert!(unsupported::<Vec<u8>>().unwrap_err().contains("unavailable"));
    }
}
