import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Pure patches are exported for node:test; importing this module never patches a project.
export function patchManifest(manifest) {
  const installPermission = '    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />';
  const queries = `    <queries>
        <intent>
            <action android:name="android.intent.action.VIEW" />
            <data android:mimeType="application/vnd.android.package-archive" />
        </intent>
    </queries>`;
  if (!manifest.includes("android.permission.REQUEST_INSTALL_PACKAGES")) {
    manifest = manifest.replace(
      '    <uses-permission android:name="android.permission.INTERNET" />',
      `    <uses-permission android:name="android.permission.INTERNET" />\n${installPermission}`,
    );
  }
  if (!manifest.includes("application/vnd.android.package-archive")) {
    manifest = manifest.replace("    <application", `${queries}\n\n    <application`);
  }
  return manifest;
}

export function patchFilePaths(paths) {
  return paths.includes('name="updates"') ? paths : paths.replace(
    "</paths>", '  <cache-path name="updates" path="." />\n</paths>',
  );
}

export function patchProguard(rules) {
  // These classes are only reachable through JNI and Tauri's reflective plugin loader.
  const bridge = [
    "-keep class com.sealbox.mobile.NdkContext { *; }",
    "-keep class com.sealbox.mobile.MobileContextPlugin { *; }",
    "-keep class com.sealbox.mobile.DocumentsPlugin { *; }",
    "-keep class com.sealbox.mobile.ApkInstaller { *; }",
  ];
  const missing = bridge.filter((rule) => !rules.includes(rule));
  if (missing.length === 0) return rules;
  return `${rules.trimEnd()}\n\n# Android context bridge and SAF plugin reflection.\n${missing.join("\n")}\n`;
}

export function patchAppGradle(appGradle, rootDirRel) {
  // Tauri derives the Gradle working directory from the Cargo workspace root.
  // Point rustBuild at the mobile crate instead of the desktop configuration.
  if (!/rootDirRel = "[^"]*"/.test(appGradle)) {
    throw new Error("Could not find rootDirRel in Android app Gradle module");
  }
  appGradle = appGradle.replace(/rootDirRel = "[^"]*"/, `rootDirRel = "${rootDirRel}"`);
  if (!appGradle.includes("signingConfigs")) {
    if (!appGradle.includes("    buildTypes {")) {
      throw new Error("Could not find the Android build types block");
    }
    appGradle = appGradle.replace(
      "    buildTypes {",
      `    signingConfigs {
        if (rootProject.file("keystore.properties").exists()) {
            create("release") {
                val keystorePropertiesFile = rootProject.file("keystore.properties")
                val keystoreProperties = Properties()
                keystoreProperties.load(FileInputStream(keystorePropertiesFile))
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["password"] as String
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["password"] as String
            }
        }
    }
    buildTypes {`,
    );
  }
  if (!appGradle.includes("signingConfig =")) {
    appGradle = appGradle.replace(
      /(getByName\("release"\) \{\r?\n)/,
      `$1            signingConfigs.findByName("release")?.let { signingConfig = it }\n`,
    );
  }
  if (!appGradle.includes("import java.io.FileInputStream")) {
    appGradle = appGradle.replace(
      "import java.util.Properties",
      "import java.io.FileInputStream\nimport java.util.Properties",
    );
  }
  return appGradle;
}

export function patchRootGradle(rootGradle) {
  // Biometry's kotlinx-coroutines 1.10.2 requires Kotlin 2.x, not template 1.9.25.
  const kotlinGradlePlugin = /org\.jetbrains\.kotlin:kotlin-gradle-plugin:[^"]+/;
  if (!kotlinGradlePlugin.test(rootGradle)) {
    throw new Error("Could not find the Kotlin Gradle plugin in Android root Gradle module");
  }
  return rootGradle.replace(kotlinGradlePlugin, "org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.10");
}

function writeChanged(path, text) {
  if (!existsSync(path) || readFileSync(path, "utf8") !== text) writeFileSync(path, text);
}

export function applyAndroidPatches(projectRoot = root) {
  const mobileDir = resolve(projectRoot, "src-tauri-mobile");
  const appModuleDir = resolve(mobileDir, "gen/android/app");
  const manifestPath = resolve(appModuleDir, "src/main/AndroidManifest.xml");
  const pathsFile = resolve(appModuleDir, "src/main/res/xml/file_paths.xml");
  const appGradlePath = resolve(appModuleDir, "build.gradle.kts");
  const rootGradlePath = resolve(mobileDir, "gen/android/build.gradle.kts");
  const proguardPath = resolve(appModuleDir, "proguard-rules.pro");
  const kotlinTargetDir = resolve(appModuleDir, "src/main/java/com/sealbox/mobile");
  // Every tracked Kotlin template is copied verbatim; the generated project is disposable.
  const kotlinTemplates = ["DocumentsPlugin.kt", "MobileContext.kt", "ApkInstaller.kt"].map((name) => ({
    source: resolve(mobileDir, "android", name),
    target: resolve(kotlinTargetDir, name),
  }));
  for (const path of [
    manifestPath,
    appGradlePath,
    rootGradlePath,
    ...kotlinTemplates.map((template) => template.source),
  ]) {
    if (!existsSync(path)) throw new Error(`Android project or Kotlin template is missing: ${path}`);
  }
  // Read and validate all inputs before writing. No MainActivity modification is necessary.
  const manifest = patchManifest(readFileSync(manifestPath, "utf8"));
  const paths = existsSync(pathsFile) ? patchFilePaths(readFileSync(pathsFile, "utf8")) : null;
  const rootDirRel = relative(appModuleDir, mobileDir).split(sep).join("/");
  const appGradle = patchAppGradle(readFileSync(appGradlePath, "utf8"), rootDirRel);
  const rootGradle = patchRootGradle(readFileSync(rootGradlePath, "utf8"));
  const proguard = existsSync(proguardPath)
    ? patchProguard(readFileSync(proguardPath, "utf8"))
    : null;
  const templates = kotlinTemplates.map((template) => ({
    ...template,
    content: readFileSync(template.source, "utf8"),
  }));
  writeChanged(manifestPath, manifest);
  if (paths !== null) writeChanged(pathsFile, paths);
  writeChanged(appGradlePath, appGradle);
  writeChanged(rootGradlePath, rootGradle);
  if (proguard !== null) writeChanged(proguardPath, proguard);
  mkdirSync(kotlinTargetDir, { recursive: true });
  for (const template of templates) writeChanged(template.target, template.content);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    applyAndroidPatches();
    console.log("patched Android install permission, Gradle working directory, Kotlin version, SAF template, APK installer and the Android context bridge");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
