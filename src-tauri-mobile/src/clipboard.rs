#[cfg(not(target_os = "android"))]
mod host {
    use std::process::Command;

    fn clip(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut command = Command::new("cmd");
        command.args(args);
        if stdin.is_some() {
            command.stdin(std::process::Stdio::piped());
        }
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .ok_or("clipboard stdin unavailable")?
                .write_all(text.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        let output = child.wait_with_output().map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn write_text(text: &str) -> Result<(), String> {
        clip(&["/C", "clip"], Some(text)).map(|_| ())
    }

    pub fn read_text() -> Result<String, String> {
        Ok(clip(
            &["/C", "powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
            None,
        )?
        .trim_end_matches(['\r', '\n'])
        .to_string())
    }
}

#[cfg(target_os = "android")]
mod host {
    use jni::objects::{JObject, JString};
    use jni::JNIEnv;

    fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T, String>) -> Result<T, String> {
        let context = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(context.vm() as *mut _) }
            .map_err(|error| error.to_string())?;
        let mut env = vm.attach_current_thread().map_err(|error| error.to_string())?;
        f(&mut env)
    }

    pub fn write_text(text: &str) -> Result<(), String> {
        with_env(|env| {
            let context = unsafe { JObject::from_raw(ndk_context::android_context().context() as _) };
            let service = env
                .new_string("clipboard")
                .map_err(|error| error.to_string())?;
            let manager = env
                .call_method(
                    &context,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[(&service).into()],
                )
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            let label = env.new_string("sealbox").map_err(|error| error.to_string())?;
            let value = env.new_string(text).map_err(|error| error.to_string())?;
            let clip = env
                .call_static_method(
                    "android/content/ClipData",
                    "newPlainText",
                    "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
                    &[(&label).into(), (&value).into()],
                )
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            env.call_method(
                manager,
                "setPrimaryClip",
                "(Landroid/content/ClipData;)V",
                &[(&clip).into()],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
    }

    pub fn read_text() -> Result<String, String> {
        with_env(|env| {
            let context = unsafe { JObject::from_raw(ndk_context::android_context().context() as _) };
            let service = env.new_string("clipboard").map_err(|error| error.to_string())?;
            let manager = env
                .call_method(
                    &context,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[(&service).into()],
                )
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            let clip = env
                .call_method(manager, "getPrimaryClip", "()Landroid/content/ClipData;", &[])
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            if clip.is_null() {
                return Ok(String::new());
            }
            let item = env
                .call_method(&clip, "getItemAt", "(I)Landroid/content/ClipData$Item;", &[0.into()])
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            let text = env
                .call_method(&item, "getText", "()Ljava/lang/CharSequence;", &[])
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            if text.is_null() {
                return Ok(String::new());
            }
            let string = env
                .call_method(&text, "toString", "()Ljava/lang/String;", &[])
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            let value = JString::from(string);
            let text = env.get_string(&value).map_err(|error| error.to_string())?;
            Ok(text.into())
        })
    }
}

pub fn write_text(text: &str) -> Result<(), String> {
    host::write_text(text)
}

pub fn read_text() -> Result<String, String> {
    host::read_text()
}

pub fn clear() -> Result<(), String> {
    host::write_text("")
}
