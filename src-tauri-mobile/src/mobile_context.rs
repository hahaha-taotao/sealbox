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

/// Registers the Kotlin bridge that publishes the Android context.
///
/// Registration is not the only chance to publish, and not a reliable one: `register_android_plugin`
/// instantiates the Kotlin class and calls `Plugin.load(webView)` from inside Tauri's plugin setup,
/// and that hop can be skipped or throw depending on what the generated project looks like. Taking
/// the whole app down over a helper that only three JNI paths need is the wrong trade, so a failure
/// is logged and the app boots.
///
/// The reliable source is `run_on_android_context`, which hands us the activity and webview
/// directly from the runtime — no Kotlin and no `load()` involved. `lib.rs` calls [`remember_app`]
/// from the builder's own `setup` to use it, and the commands retry through [`ensure_ready`].
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

/// Last chance for a command that needs the context.
///
/// `MobileContextPlugin.load` and the builder-time attempt both normally publish it before any
/// command runs, so this is a safety net rather than the common path: it tries once, at most
/// every five seconds, and never blocks a caller for long. A command that finds `is_ready() ==
/// false` after this still reports its own fixed sentence, which is better than a UI that waits
/// seconds on every attempt to copy a password.
#[cfg(target_os = "android")]
pub fn ensure_ready() {
    if is_ready() || app_handle().is_none() {
        return;
    }
    // Concurrent commands would otherwise each queue their own retry behind the same main pipe.
    let _guard = match RETRY_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if is_ready() {
        return;
    }
    let now = std::time::Instant::now();
    if RETRY_AT
        .lock()
        .map(|last| now.duration_since(*last) < RETRY_INTERVAL)
        .unwrap_or(false)
    {
        return;
    }
    if let Ok(mut last) = RETRY_AT.lock() {
        *last = now;
    }
    if let Some(app) = app_handle() {
        // Bounded, and on the caller's own thread: this is a command, never the main thread.
        publish_through_runtime(&app);
    }
}

/// How often a command may re-attempt the runtime path. Only Android retries.
#[cfg(target_os = "android")]
const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(target_os = "android")]
static RETRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(target_os = "android")]
static RETRY_AT: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
#[cfg(target_os = "android")]
static APP: std::sync::Mutex<Option<tauri::AppHandle<tauri::Wry>>> = std::sync::Mutex::new(None);

/// Remembers the handle for [`ensure_ready`] and makes the first attempt.
///
/// The attempt is started, not awaited: `run_on_android_context` posts to the Android main pipe,
/// so waiting for the answer on the main thread would deadlock against itself. The `setup` hook
/// that calls this runs on the main thread, hence the detached thread.
#[cfg(target_os = "android")]
pub fn remember_app(app: &tauri::AppHandle<tauri::Wry>) {
    if let Ok(mut slot) = APP.lock() {
        *slot = Some(app.clone());
    }
    let handle = app.clone();
    std::thread::spawn(move || publish_through_runtime(&handle));
}

#[cfg(target_os = "android")]
fn app_handle() -> Option<tauri::AppHandle<tauri::Wry>> {
    APP.lock().ok().and_then(|slot| slot.clone())
}

/// One round trip on the Android context thread that hands `publish` the application context.
///
/// Must not run on the main thread: see [`remember_app`].
#[cfg(target_os = "android")]
fn publish_through_runtime(app: &tauri::AppHandle<tauri::Wry>) {
    if is_ready() {
        return;
    }
    use tauri::Manager as _;
    let (done, wait) = std::sync::mpsc::channel();
    app.runtime_handle()
        .run_on_android_context(move |env, activity, _webview| {
            // `ndk-context` holds this reference for the whole process, so it must be the
            // application context rather than the activity: an activity is destroyed on rotation
            // or when the task goes away, and every later JNI call would then target a dead
            // object. The Kotlin bridge passes `activity.applicationContext` for the same reason.
            let outcome = application_context(env, activity)
                .and_then(|context| publish(env, &context).map_err(|error| error.to_string()));
            let _ = done.send(outcome);
        });
    match wait.recv_timeout(std::time::Duration::from_millis(5000)) {
        Ok(Ok(())) => {}
        Ok(Err(detail)) => report("runtime context publish failed", &detail),
        Err(_) => report(
            "runtime context publish timed out",
            "run_on_android_context did not answer within 5s",
        ),
    }
}

/// `activity.getApplicationContext()`, as a local reference valid for the caller's frame.
#[cfg(target_os = "android")]
fn application_context<'local>(
    env: &mut jni::JNIEnv<'local>,
    activity: &jni::objects::JObject<'_>,
) -> Result<jni::objects::JObject<'local>, String> {
    env.call_method(
        activity,
        "getApplicationContext",
        "()Landroid/content/Context;",
        &[],
    )
    .and_then(|value| value.l())
    .map_err(|error| format!("getApplicationContext failed: {error}"))
}

/// Whether the JNI helpers have a context to use. They fail with an error instead of panicking.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn is_ready() -> bool {
    READY.load(Ordering::SeqCst)
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
    Ok(())
}
