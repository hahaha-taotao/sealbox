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
pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("mobile-context")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            _api.register_android_plugin("com.sealbox.mobile", "MobileContextPlugin")?;
            Ok(())
        })
        .build()
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
    env: jni::JNIEnv<'local>,
    _class: jni::objects::JClass<'local>,
    context: jni::objects::JObject<'local>,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        publish(&env, &context).map_err(|error| error.to_string())
    }));
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("sealbox: Android context is unavailable: {error}"),
        Err(_) => eprintln!("sealbox: Android context initialization panicked"),
    }
}

fn publish(env: &jni::JNIEnv<'_>, context: &jni::objects::JObject<'_>) -> jni::errors::Result<()> {
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
