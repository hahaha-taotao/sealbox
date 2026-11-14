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
const centralMirror = "https://maven-central.storage-download.googleapis.com/maven2/";
const rootGradle = `buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.25")
    }
}
allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
`;
const buildSrcGradle = `plugins {
    \`kotlin-dsl\`
}
repositories {
    google()
    mavenCentral()
}
dependencies {
    implementation("com.android.tools.build:gradle:8.11.0")
}
`;

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
    put(join(app, "../buildSrc/build.gradle.kts"), buildSrcGradle);
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

// Exercise the public file-patching boundary, not private Gradle transformation helpers.
function withGradleProject(run) {
  const root = mkdtempSync(join(tmpdir(), "sealbox-gradle-repositories-"));
  const android = join(root, "src-tauri-mobile/gen/android");
  const put = (relativePath, content) => {
    const path = join(android, relativePath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  };
  const read = (relativePath) => readFileSync(join(android, relativePath), "utf8");
  try {
    put("app/src/main/AndroidManifest.xml", manifest);
    put("app/build.gradle.kts", appGradle);
    put("build.gradle.kts", rootGradle);
    put("buildSrc/build.gradle.kts", buildSrcGradle);
    for (const name of ["DocumentsPlugin.kt", "MobileContext.kt", "ApkInstaller.kt"]) {
      put(`../../android/${name}`, `// authoritative ${name}\n`);
    }
    run({ root, android, put, read });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function assertMirrorFirst(repositories, fallback) {
  assert.ok(repositories.includes(centralMirror), "Central mirror must exist in this repository scope");
  assert.ok(repositories.includes(fallback), `${fallback} must remain available`);
  assert.ok(repositories.indexOf(centralMirror) < repositories.indexOf(fallback),
    `Central mirror must precede ${fallback}`);
}

function assertPluginRepositories(settings) {
  const management = settings.match(/pluginManagement\s*\{\s*repositories\s*\{([^{}]+)\}/);
  assert.ok(management, "buildSrc needs its own settings pluginManagement repositories before kotlin-dsl resolves");
  assertMirrorFirst(management[1], "gradlePluginPortal()");
  assertMirrorFirst(management[1], "google()");
}

test("fresh buildSrc resolves kotlin-dsl through independent pluginManagement and all Central scopes prefer the mirror", () => {
  withGradleProject(({ root, put, read }) => {
    // A root settings repository is not inherited by the separate buildSrc build.
    const rootSettings = 'pluginManagement { repositories { gradlePluginPortal() } }\nrootProject.name = "custom-root"\n';
    put("settings.gradle.kts", rootSettings);
    applyAndroidPatches(root);
    assertPluginRepositories(read("buildSrc/settings.gradle.kts"));
    const rootBuild = read("build.gradle.kts");
    const scopes = [...rootBuild.matchAll(/repositories\s*\{([^}]+)\}/g)];
    assert.equal(scopes.length, 2, "both root buildscript and allprojects remain present");
    for (const [, repositories] of scopes) {
      assertMirrorFirst(repositories, "mavenCentral()");
      assert.ok(repositories.includes("google()"));
    }
    const buildSrc = read("buildSrc/build.gradle.kts");
    const repositories = buildSrc.match(/repositories\s*\{([^}]+)\}/)?.[1];
    assert.ok(repositories);
    assertMirrorFirst(repositories, "mavenCentral()");
    assert.ok(repositories.includes("google()"));
    assert.ok(buildSrc.includes("`kotlin-dsl`"));
    assert.ok(buildSrc.includes('implementation("com.android.tools.build:gradle:8.11.0")'));
    assert.equal(read("settings.gradle.kts"), rootSettings);
    const paths = ["build.gradle.kts", "buildSrc/build.gradle.kts", "buildSrc/settings.gradle.kts"];
    const first = paths.map(read);
    applyAndroidPatches(root);
    assert.deepEqual(paths.map(read), first, "repository patches are byte-for-byte idempotent");
  });
});

test("existing buildSrc settings retain unrelated configuration and custom plugin repositories", () => {
  for (const prefix of ["", `pluginManagement {
    repositories {
        gradlePluginPortal()
        maven("https://plugins.example.invalid/maven")
    }
    resolutionStrategy {
        eachPlugin { if (requested.id.id == "custom") useModule("org.example:plugin:1.0") }
    }
}
`]) {
    withGradleProject(({ root, put, read }) => {
      const retained = '// existing project configuration\nrootProject.name = "custom-build-src"\ninclude(":helper")\n';
      put("buildSrc/settings.gradle.kts", prefix + retained);
      applyAndroidPatches(root);
      const settings = read("buildSrc/settings.gradle.kts");
      assertPluginRepositories(settings);
      assert.ok(settings.includes(retained), "existing settings must not be replaced");
      if (prefix) {
        assert.ok(settings.includes('maven("https://plugins.example.invalid/maven")'));
        assert.ok(settings.includes('eachPlugin { if (requested.id.id == "custom") useModule("org.example:plugin:1.0") }'));
      }
      applyAndroidPatches(root);
      assert.equal(read("buildSrc/settings.gradle.kts"), settings);
    });
  }
});

test("unsupported buildSrc settings or repository layouts fail before any project file is changed", () => {
  const cases = [
    ["buildSrc/settings.gradle", 'rootProject.name = "groovy-build-src"\n'],
    ["buildSrc/settings.gradle.kts", "pluginManagement { configurePluginRepositories() }\n"],
    ["buildSrc/build.gradle.kts", "plugins { `kotlin-dsl` }\nconfigureRepositories()\n"],
    ["build.gradle.kts", 'classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.25")\n'],
  ];
  for (const [invalidPath, invalidContent] of cases) {
    withGradleProject(({ root, put, read }) => {
      put(invalidPath, invalidContent);
      const paths = ["app/src/main/AndroidManifest.xml", "app/build.gradle.kts", "build.gradle.kts", "buildSrc/build.gradle.kts", invalidPath];
      const before = paths.map(read);
      assert.throws(() => applyAndroidPatches(root), /buildSrc|settings|repositories|Gradle/i,
        `unsupported ${invalidPath} must fail explicitly`);
      assert.deepEqual(paths.map(read), before, "validation must happen before any writes");
    });
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
  assert.match(kotlin, /NdkContext\.initializeQuietly\(activity\.applicationContext\)/);
  assert.match(kotlin, /System\.loadLibrary\("sealbox_mobile_lib"\)/);
  assert.match(kotlin, /@JvmStatic\s+external fun initialize\(context: Context\)/);
});

test("Android context bridge survives a failing load() hook", () => {
  const kotlin = readFileSync(new URL("../src-tauri-mobile/android/MobileContext.kt", import.meta.url), "utf8");
  // Both the library load and the JNI call are wrapped: an exception escaping load() fails Tauri's
  // plugin registration, and one escaping a lifecycle callback kills the process.
  assert.match(kotlin, /try\s*{[^}]*System\.loadLibrary\([^)]*\)[^}]*}\s*catch\s*\(\w+: Throwable\)/);
  assert.match(kotlin, /fun initializeQuietly\(context: Context\)\s*{[^}]*try\s*{[^}]*initialize\([^)]*\)/);
  // A framework-driven second path, independent of Tauri's plugin registration.
  assert.match(kotlin, /registerActivityLifecycleCallbacks/);
  assert.match(kotlin, /override fun onActivityCreated\(activity: Activity, savedInstanceState: Bundle\?\)/);
  assert.match(kotlin, /if \(watching\) return/);
});
