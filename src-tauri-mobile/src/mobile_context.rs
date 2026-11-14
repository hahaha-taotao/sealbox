//! Publishes the Android application context for the crate's JNI helpers.
//!
//! Tauri 2.11 ships tao 0.35, which no longer initializes `ndk-context` (tao 0.36 restores it with
//! an Application context). Without this, `clipboard`, `saf` and `update` panic on
//! `ndk_context::android_context()`. The Kotlin `MobileContextPlugin` calls the exported
//! `NdkContext.initialize` while the webview is created, before any command can run. The export is
//! compiled on every target so host `cargo check`/`cargo test` type-check it; only Android calls it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

static READY: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();
/// Fixed description of the last bridge failure, or empty. Never holds a credential or a raw
/// server/JVM reply: it is shown in the settings page and would otherwise be a leak vector.
static LAST_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Registers the Kotlin bridge that publishes the Android context.
///
/// Registration is not the only chance to publish, and not a reliable one: `register_android_plugin`
/// instantiates the Kotlin class and calls `Plugin.load(webView)` from inside Tauri's plugin setup,
/// and that hop can be skipped or throw depending on what the generated project looks like. Taking
/// the whole app down over a helper that only three JNI paths need is the wrong trade, so a failure
/// is logged and the app boots.
///
/// The second chance is the Kotlin side's own `Application.ActivityLifecycleCallbacks`, registered
/// from `load`: the framework drives `onActivityCreated` itself, so it survives whatever the plugin
/// registration did or did not do. There is deliberately no Rust-side fallback — the runtime handle
/// that could reach the activity (`ManagerBase::runtime`) is sealed inside Tauri, and a path that
/// cannot be compiled against the real Android target is worse than no path at all.
pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("mobile-context")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            if let Err(error) = _api.register_android_plugin("com.sealbox.mobile", "MobileContextPlugin") {
                report("plugin registration failed", &error.to_string());
            }
            Ok(())
        })
        .build()
}

/// Records a context-bridge failure where `adb logcat` can see it.
///
/// The three callers render a Chinese sentence instead of the raw reason ("Android 上下文未就绪"),
/// which is right for the UI but leaves nothing to debug from. Logcat is the only channel that
/// outlives a field report.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn report(what: &str, detail: &str) {
    // Only the fixed tag reaches the UI. `detail` can quote the JVM, and the settings page is not a
    // place to dump that.
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(what.to_string());
    }
    // Always on stderr as well: a Rust panic or an early failure can happen before the JVM lets us
    // talk to it, and `adb logcat -s RustStdoutStderr` shows this form too.
    eprintln!("sealbox context bridge: {what}: {detail}");
    #[cfg(target_os = "android")]
    {
        // Best effort only. Logcat needs the VM, which is exactly what may be missing here, so
        // every step degrades to the stderr line above instead of propagating.
        let context = match std::panic::catch_unwind(|| ndk_context::android_context()) {
            Ok(context) => context,
            Err(_) => return,
        };
        let Ok(vm) = (unsafe { jni::JavaVM::from_raw(context.vm() as *mut _) }) else {
            return;
        };
        let Ok(mut env) = vm.attach_current_thread() else {
            return;
        };
        let Ok(tag) = env.new_string("Sealbox") else {
            return;
        };
        let Ok(message) = env.new_string(format!("{what}: {detail}")) else {
            return;
        };
        let _ = env.call_static_method(
            "android/util/Log",
            "e",
            "(Ljava/lang/String;Ljava/lang/String;)I",
            &[(&jni::objects::JObject::from(tag)).into(), (&jni::objects::JObject::from(message)).into()],
        );
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }
}

/// Whether the JNI helpers have a context to use. They fail with an error instead of panicking.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn is_ready() -> bool {
    READY.load(Ordering::SeqCst)
}

/// The last published failure, for the settings page.
///
/// The three callers show one fixed Chinese sentence ("Android 上下文未就绪"), which is right for
/// the action but says nothing about which step broke. This string is the missing half: a fixed
/// tag chosen here, never anything the JVM or the server said.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn last_error() -> String {
    LAST_ERROR
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_default()
}

/// `com.sealbox.mobile.NdkContext.initialize(applicationContext)`.
///
/// Never unwind into the JVM: a panic across the JNI boundary aborts the app process.
#[no_mangle]
pub extern "system" fn Java_com_sealbox_mobile_NdkContext_initialize<'local>(
    mut env: jni::JNIEnv<'local>,
    _class: jni::objects::JClass<'local>,
    context: jni::objects::JObject<'local>,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        publish(&mut env, &context).map_err(|error| error.to_string())
    }));
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("sealbox: Android context is unavailable: {error}"),
        Err(_) => eprintln!("sealbox: Android context initialization panicked"),
    }
}

fn publish(env: &mut jni::JNIEnv<'_>, context: &jni::objects::JObject<'_>) -> jni::errors::Result<()> {
    if INIT.is_completed() {
        return Ok(());
    }
    if context.as_raw().is_null() {
        return Err(jni::errors::Error::NullPtr("Android application context"));
    }
    let vm = env.get_java_vm()?;
    // The published pointer lives for the whole process, so leak the global reference instead of
    // freeing it when this guard is dropped.
    let global = env.new_global_ref(context)?;
    let raw = global.as_obj().as_raw();
    std::mem::forget(global);
    INIT.call_once(|| unsafe {
        ndk_context::initialize_android_context(vm.get_java_vm_pointer().cast(), raw.cast());
    });
    READY.store(true, Ordering::SeqCst);
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = None;
    }
    Ok(())
}
