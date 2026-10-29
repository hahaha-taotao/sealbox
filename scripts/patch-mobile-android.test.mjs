import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  applyAndroidPatches, patchManifest, patchFilePaths, patchAppGradle, patchRootGradle, patchProguard,
} from "./patch-mobile-android.mjs";

const manifest = `<manifest>
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="existing">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>`;
const appGradle = `import java.util.Properties
android {
    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }
}
tauri { rootDirRel = "../../../../" }
`;
const rootGradle = 'classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.25")\n';

// Importing the patch module above must be inert; fixtures are the only write targets.
test("pure Android patches are idempotent and retain existing activity configuration", () => {
  const patchedManifest = patchManifest(manifest);
  assert.equal(patchManifest(patchedManifest), patchedManifest);
  assert.match(patchedManifest, /REQUEST_INSTALL_PACKAGES/);
  assert.match(patchedManifest, /application\/vnd.android.package-archive/);
  assert.ok(patchedManifest.includes('<activity android:name=".MainActivity" android:exported="true" />'));
  assert.ok(!patchedManifest.includes("MANAGE_EXTERNAL_STORAGE"));
  assert.ok(!patchedManifest.includes("READ_EXTERNAL_STORAGE"));
  const paths = patchFilePaths('<paths>\n  <files-path name="existing" path="." />\n</paths>');
  assert.equal(patchFilePaths(paths), paths);
  assert.match(paths, /name="existing"/);
  assert.match(paths, /name="updates"/);
  const gradle = patchAppGradle(appGradle, "../../..");
  assert.equal(patchAppGradle(gradle, "../../.."), gradle);
  assert.match(gradle, /rootDirRel = "\.\.\/\.\.\/\.\."/);
  assert.equal(gradle.match(/import java.io.FileInputStream/g)?.length, 1);
  assert.equal(gradle.match(/signingConfig = it/g)?.length, 1);
  const kotlin = patchRootGradle(rootGradle);
  assert.equal(patchRootGradle(kotlin), kotlin);
  assert.match(kotlin, /kotlin-gradle-plugin:2.2.10/);
  const proguard = patchProguard("# project rule\n");
  assert.equal(patchProguard(proguard), proguard);
  assert.match(proguard, /# project rule/);
  assert.match(proguard, /-keep class com\.sealbox\.mobile\.NdkContext \{ \*; \}/);
  assert.match(proguard, /-keep class com\.sealbox\.mobile\.MobileContextPlugin \{ \*; \}/);
  assert.match(proguard, /-keep class com\.sealbox\.mobile\.DocumentsPlugin \{ \*; \}/);
  assert.match(proguard, /-keep class com\.sealbox\.mobile\.ApkInstaller \{ \*; \}/);
});

test("invalid Gradle inputs fail explicitly instead of silently omitting patches", () => {
  assert.throws(() => patchAppGradle("android {}", "../../.."), /rootDirRel/);
  assert.throws(() => patchAppGradle('tauri { rootDirRel = ".." }', "../../.."), /build types/);
  assert.throws(() => patchRootGradle("buildscript {}"), /Kotlin Gradle plugin/);
});

test("generated projects sync the authoritative Kotlin template without editing MainActivity", () => {
  const root = mkdtempSync(join(tmpdir(), "sealbox-saf-patch-"));
  const app = join(root, "src-tauri-mobile/gen/android/app");
  const java = join(app, "src/main/java/com/sealbox/mobile");
  const template = join(root, "src-tauri-mobile/android/DocumentsPlugin.kt");
  const target = join(java, "DocumentsPlugin.kt");
  const contextTemplate = join(root, "src-tauri-mobile/android/MobileContext.kt");
  const contextTarget = join(java, "MobileContext.kt");
  const installerTemplate = join(root, "src-tauri-mobile/android/ApkInstaller.kt");
  const installerTarget = join(java, "ApkInstaller.kt");
  const activity = join(java, "MainActivity.kt");
  const put = (path, data) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, data); };
  try {
    put(join(app, "src/main/AndroidManifest.xml"), manifest);
    put(join(app, "src/main/res/xml/file_paths.xml"), "<paths>\n</paths>");
    put(join(app, "build.gradle.kts"), appGradle);
    put(join(app, "../build.gradle.kts"), rootGradle);
    put(join(app, "proguard-rules.pro"), "# project rules\n");
    const mainActivity = "package com.sealbox.mobile\n// custom integration must survive\nclass MainActivity : TauriActivity()\n";
    put(activity, mainActivity);
    // Use the actual tracked template, not a fixture that could drift from production.
    const actualTemplate = readFileSync(new URL("../src-tauri-mobile/android/DocumentsPlugin.kt", import.meta.url), "utf8");
    const actualContextTemplate = readFileSync(new URL("../src-tauri-mobile/android/MobileContext.kt", import.meta.url), "utf8");
    const actualInstallerTemplate = readFileSync(new URL("../src-tauri-mobile/android/ApkInstaller.kt", import.meta.url), "utf8");
    put(template, actualTemplate);
    put(contextTemplate, actualContextTemplate);
    put(installerTemplate, actualInstallerTemplate);
    applyAndroidPatches(root);
    assert.equal(readFileSync(target, "utf8"), actualTemplate);
    assert.equal(readFileSync(contextTarget, "utf8"), actualContextTemplate);
    assert.equal(readFileSync(installerTarget, "utf8"), actualInstallerTemplate);
    assert.equal(readFileSync(activity, "utf8"), mainActivity);
    const proguard = readFileSync(join(app, "proguard-rules.pro"), "utf8");
    assert.match(proguard, /# project rules/);
    assert.match(proguard, /NdkContext/);
    const first = readFileSync(join(app, "build.gradle.kts"), "utf8");
    applyAndroidPatches(root);
    assert.equal(readFileSync(join(app, "build.gradle.kts"), "utf8"), first);
    assert.equal(readFileSync(target, "utf8"), actualTemplate);
    assert.equal(readFileSync(contextTarget, "utf8"), actualContextTemplate);
    assert.equal(readFileSync(installerTarget, "utf8"), actualInstallerTemplate);
    put(template, `${actualTemplate}\n// new template revision\n`);
    put(contextTemplate, `${actualContextTemplate}\n// new context template revision\n`);
    put(installerTemplate, `${actualInstallerTemplate}\n// new installer template revision\n`);
    applyAndroidPatches(root);
    assert.equal(readFileSync(target, "utf8"), readFileSync(template, "utf8"));
    assert.equal(readFileSync(contextTarget, "utf8"), readFileSync(contextTemplate, "utf8"));
    assert.equal(readFileSync(installerTarget, "utf8"), readFileSync(installerTemplate, "utf8"));
    assert.equal(readFileSync(activity, "utf8"), mainActivity);
  } finally {
    // This test owns this mkdtemp directory only.
    rmSync(root, { recursive: true, force: true });
  }
});

test("SAF template keeps bytes outside commands and uses document intents plus bounded verified streams", () => {
  const kotlin = readFileSync(new URL("../src-tauri-mobile/android/DocumentsPlugin.kt", import.meta.url), "utf8");
  assert.match(kotlin, /@Keep\s+@TauriPlugin\s+class DocumentsPlugin/);
  assert.match(kotlin, /Intent.ACTION_OPEN_DOCUMENT/);
  assert.match(kotlin, /Intent.ACTION_CREATE_DOCUMENT/);
  assert.match(kotlin, /uri.scheme == "content"/);
  assert.match(kotlin, /maxBytes - total \+ 1/);
  assert.match(kotlin, /MessageDigest.isEqual/);
  assert.match(kotlin, /createdDocuments.remove\(value\)/);
  assert.match(kotlin, /grantOwner.active = false/);
  assert.match(kotlin, /createdDocuments.entries.removeIf/);
  assert.match(kotlin, /GRANT_TTL_MS = 10 \* 60 \* 1000L/);
  assert.match(kotlin, /fun expired\(/);
  assert.match(kotlin, /grant\.expired\(\)/);
  assert.match(kotlin, /override fun onDestroy/);
  assert.match(kotlin, /pending !== invoke/);
  assert.doesNotMatch(kotlin, /@Command\s+fun (readBytes|writeNewBytes)/);
  assert.doesNotMatch(kotlin, /Base64|File\(uri|\.path\b/);
});

test("APK installer template opens FileProvider on the UI thread", () => {
  const kotlin = readFileSync(new URL("../src-tauri-mobile/android/ApkInstaller.kt", import.meta.url), "utf8");
  assert.match(kotlin, /@Keep/);
  assert.match(kotlin, /@JvmStatic/);
  assert.match(kotlin, /fun open/);
  assert.match(kotlin, /FileProvider\.getUriForFile/);
  assert.match(kotlin, /FLAG_ACTIVITY_NEW_TASK/);
  assert.match(kotlin, /runOnUiThread/);
});

test("Android context bridge publishes the application context before commands can run", () => {
  const kotlin = readFileSync(new URL("../src-tauri-mobile/android/MobileContext.kt", import.meta.url), "utf8");
  assert.match(kotlin, /@Keep\s+@TauriPlugin\s+class MobileContextPlugin/);
  assert.match(kotlin, /override fun load\(webView: WebView\)/);
  assert.match(kotlin, /NdkContext\.initialize\(activity\.applicationContext\)/);
  assert.match(kotlin, /System\.loadLibrary\("sealbox_mobile_lib"\)/);
  assert.match(kotlin, /@JvmStatic\s+external fun initialize\(context: Context\)/);
});
