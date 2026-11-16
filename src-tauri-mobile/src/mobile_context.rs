//! Adopts the Android application context for the crate's JNI helpers.
//!
//! ## Why this module must not call `initialize_android_context` first
//!
//! `ndk-context` 0.1.1 stores a single process-wide context and
//! `initialize_android_context` does `assert!(previous.is_none())`. tao 0.37
//! (what Tauri 2.12 pulls in) already calls that helper from
//! `Activity.onCreate`. If anything else — our old `ContentProvider` bridge
//! especially — publishes first, tao's later assert aborts the whole process:
//! the app opens and immediately crashes.
//!
//! That is exactly the 0.20.3–0.20.5 Android regression after upgrading from
//! 0.19.1. 0.19.1 "worked" only because our plugin ran *after* tao, the
//! double-init panic was caught inside the JNI export, and `READY` stayed
//! false — which then surfaced as "Android context not ready" on install/copy/SAF.
//!
//! ## What we do instead
//!
//! Never compete with tao. The Kotlin hooks (`ContentProvider`, plugin
//! `load`, activity lifecycle) only *nudge* us to look; we adopt whatever
//! `ndk_context::android_context()` already has and flip `READY`. Commands
//! call `is_ready()`, which also tries to adopt on demand, so a missed nudge
//! is not fatal.
//!
//! The JNI export still exists so the Kotlin templates keep compiling against
//! one symbol; it is now an adopt/retry signal, not a competing initializer.

use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);
static PROBE: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Fixed description of the last bridge failure, or empty. Never holds a credential or a raw
/// server/JVM reply: it is shown in the settings page and would otherwise be a leak vector.
static LAST_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Registers the Kotlin bridge that nudges us to adopt the Android context.
///
/// Registration is not the only chance, and not a reliable one: `register_android_plugin`
/// instantiates the Kotlin class and calls `Plugin.load(webView)` from inside Tauri's plugin setup,
/// and that hop can be skipped or throw depending on what the generated project looks like. Taking
/// the whole app down over a helper that only three JNI paths need is the wrong trade, so a failure
/// is logged and the app boots.
///
/// The second chance is the Kotlin side's own `Application.ActivityLifecycleCallbacks`, registered
/// from `load`: the framework drives `onActivityCreated` itself, so it survives whatever the plugin
/// registration did or did not do. There is deliberately no Rust-side fallback that reaches into
/// Tauri's sealed runtime — and deliberately no call to `initialize_android_context`, which would
/// race tao and abort the process.
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

/// True once `ndk-context` has a context we can use (ours or tao's).
///
/// Also tries to adopt on demand: the Kotlin nudge can fire before
/// `Activity.onCreate`, and commands must not stay blocked just because the
/// early call saw an empty slot.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn is_ready() -> bool {
    if READY.load(Ordering::SeqCst) {
        return true;
    }
    adopt_if_present()
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
/// Never calls `ndk_context::initialize_android_context` — see module docs.
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
        Err(_) => eprintln!("sealbox: Android context adopt panicked"),
    }
}

/// Adopt tao's (or any earlier) `ndk-context` publication. Never initializes.
///
/// `android_context()` uses `expect`, so a miss panics; we catch that. The panic hook is
/// silenced for the probe so early ContentProvider nudges do not spam logcat before tao runs.
fn adopt_if_present() -> bool {
    let present = {
        let _guard = PROBE.lock().unwrap_or_else(|poison| poison.into_inner());
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(|| ndk_context::android_context());
        std::panic::set_hook(previous);
        outcome.is_ok()
    };
    if !present {
        return false;
    }
    READY.store(true, Ordering::SeqCst);
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = None;
    }
    true
}

fn publish(env: &mut jni::JNIEnv<'_>, context: &jni::objects::JObject<'_>) -> jni::errors::Result<()> {
    if READY.load(Ordering::SeqCst) || adopt_if_present() {
        return Ok(());
    }
    // ContentProvider can run before Activity.onCreate; tao has not published yet.
    // Returning Ok keeps the Kotlin side quiet — `is_ready()` will adopt later.
    // Passing a null context is still a hard error so bad JNI bindings stay visible.
    if context.as_raw().is_null() {
        return Err(jni::errors::Error::NullPtr("Android application context"));
    }
    let _ = env; // JNI env kept in the signature so the export shape stays stable for Kotlin.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_build_has_no_android_context_to_adopt() {
        // On desktop/CI hosts `android_context()` panics; adopt must stay false and must not
        // poison READY. Re-entry must keep being safe — commands call `is_ready()` often.
        assert!(!adopt_if_present());
        assert!(!is_ready());
        assert!(!adopt_if_present());
        assert!(!is_ready());
        assert!(last_error().is_empty());
    }
}
