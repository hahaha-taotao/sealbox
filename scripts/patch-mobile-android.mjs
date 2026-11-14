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
  // The context bridge's only unconditional hook. A provider is instantiated by the framework
  // before `Application.onCreate`, so it runs even when Tauri's plugin registration does not.
  const provider = '        <provider\n' +
    '            android:name="com.sealbox.mobile.ContextBootstrapProvider"\n' +
    '            android:authorities="${applicationId}.context-bootstrap"\n' +
    '            android:exported="false" />';
  if (!manifest.includes("ContextBootstrapProvider")) {
    const applicationOpen = manifest.match(/<application[^>]*>/);
    if (applicationOpen === null) throw new Error("Could not find the manifest application element");
    const at = applicationOpen.index + applicationOpen[0].length;
    manifest = `${manifest.slice(0, at)}\n${provider}${manifest.slice(at)}`;
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
    "-keep class com.sealbox.mobile.ContextBootstrapProvider { *; }",
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

const centralMirror = "https://maven-central.storage-download.googleapis.com/maven2/";

// Deliberately support flat generated repository blocks, not arbitrary Kotlin DSL.
// Unknown layouts fail before applyAndroidPatches writes any project files.
function patchRepositories(gradle, expectedCount, label, pluginRepositories = false) {
  const blocks = [...gradle.matchAll(/\brepositories\s*\{([^{}]*)\}/g)];
  const openings = gradle.match(/\brepositories\s*\{/g) ?? [];
  if (blocks.length !== expectedCount || openings.length !== expectedCount) {
    throw new Error(`Unsupported ${label} repositories layout`);
  }
  return gradle.replace(/\brepositories\s*\{([^{}]*)\}/g, (block, body) => {
    // Validate whole lines so URL slashes are never treated as comments.
    const lines = body.split(/\r?\n/);
    const supported = lines.every((line) => !line.trim() || /^\s*\/\//.test(line)
      || /^\s*(?:google|mavenCentral|gradlePluginPortal)\(\)\s*$/.test(line)
      || /^\s*maven\("[^"\r\n]+"\)\s*$/.test(line));
    if (!supported) {
      throw new Error(`Unsupported ${label} repositories contents`);
    }
    const mirrorLine = `maven("${centralMirror}")`;
    const existing = lines.filter((line) => line.trim() !== mirrorLine);
    const indent = lines.find((line) => /^\s+\S/.test(line))?.match(/^\s*/)[0] ?? "        ";
    const missing = pluginRepositories
      ? ["google()", "gradlePluginPortal()"].filter((call) => !existing.some((line) => line.trim() === call))
      : [];
    const content = existing.join("\n").replace(/^\s*\n/, "");
    return `repositories {\n${indent}${mirrorLine}\n${missing.map((call) => `${indent}${call}\n`).join("")}${content}}`;
  });
}

function patchBuildSrcSettings(settings) {
  if (!/\bpluginManagement\b/.test(settings)) {
    // The generated build has no settings. Preserve simple existing project identity
    // and includes; refuse executable/unknown settings rather than guessing ordering.
    if (!settings.split(/\r?\n/).every((line) => /^\s*(?:\/\/.*|rootProject\.name\s*=\s*"[^"\r\n]*"\s*|include\([^\r\n]*\)\s*)?$/.test(line))) {
      throw new Error("Unsupported buildSrc settings layout");
    }
    return `pluginManagement {\n    repositories {\n        maven("${centralMirror}")\n        google()\n        gradlePluginPortal()\n    }\n}\n${settings}`;
  }
  if (!/^(?:\s|\/\/[^\n]*(?:\n|$))*pluginManagement\s*\{\s*repositories\s*\{/.test(settings)) {
    throw new Error("Unsupported buildSrc settings pluginManagement layout");
  }
  return patchRepositories(settings, 1, "buildSrc settings pluginManagement", true);
}

export function patchRootGradle(rootGradle) {
  // Biometry's kotlinx-coroutines 1.10.2 requires Kotlin 2.x, not template 1.9.25.
  const kotlinGradlePlugin = /org\.jetbrains\.kotlin:kotlin-gradle-plugin:[^"]+/;
  if (!kotlinGradlePlugin.test(rootGradle)) {
    throw new Error("Could not find the Kotlin Gradle plugin in Android root Gradle module");
  }
  if (!/\bbuildscript\s*\{\s*repositories\s*\{/.test(rootGradle)
    || !/\ballprojects\s*\{\s*repositories\s*\{/.test(rootGradle)) {
    throw new Error("Unsupported Android root Gradle repositories layout");
  }
  return patchRepositories(rootGradle, 2, "Android root Gradle")
    .replace(kotlinGradlePlugin, "org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.10");
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
  const buildSrcGradlePath = resolve(mobileDir, "gen/android/buildSrc/build.gradle.kts");
  const buildSrcSettingsPath = resolve(mobileDir, "gen/android/buildSrc/settings.gradle.kts");
  const buildSrcGroovySettingsPath = resolve(mobileDir, "gen/android/buildSrc/settings.gradle");
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
    buildSrcGradlePath,
    ...kotlinTemplates.map((template) => template.source),
  ]) {
    if (!existsSync(path)) throw new Error(`Android project or Kotlin template is missing: ${path}`);
  }
  if (existsSync(buildSrcGroovySettingsPath)) {
    throw new Error("Unsupported buildSrc settings.gradle; refusing to replace existing Groovy settings");
  }
  // Read and validate all inputs before writing. No MainActivity modification is necessary.
  const manifest = patchManifest(readFileSync(manifestPath, "utf8"));
  const paths = existsSync(pathsFile) ? patchFilePaths(readFileSync(pathsFile, "utf8")) : null;
  const rootDirRel = relative(appModuleDir, mobileDir).split(sep).join("/");
  const appGradle = patchAppGradle(readFileSync(appGradlePath, "utf8"), rootDirRel);
  const rootGradle = patchRootGradle(readFileSync(rootGradlePath, "utf8"));
  const buildSrcGradle = patchRepositories(readFileSync(buildSrcGradlePath, "utf8"), 1, "buildSrc Gradle");
  // kotlin-dsl dependencies resolve before buildSrc/build.gradle.kts is evaluated.
  // Root project repositories cannot configure this independent plugin resolution.
  const buildSrcSettings = patchBuildSrcSettings(existsSync(buildSrcSettingsPath)
    ? readFileSync(buildSrcSettingsPath, "utf8") : "");
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
  writeChanged(buildSrcGradlePath, buildSrcGradle);
  writeChanged(buildSrcSettingsPath, buildSrcSettings);
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
