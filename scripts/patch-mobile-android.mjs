import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = resolve(root, "src-tauri-mobile/gen/android/app/src/main/AndroidManifest.xml");
const pathsFile = resolve(root, "src-tauri-mobile/gen/android/app/src/main/res/xml/file_paths.xml");
const appModuleDir = resolve(root, "src-tauri-mobile/gen/android/app");
const appGradlePath = resolve(appModuleDir, "build.gradle.kts");
const mobileDir = resolve(root, "src-tauri-mobile");

const installPermission = '    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />';
const queries = `    <queries>
        <intent>
            <action android:name="android.intent.action.VIEW" />
            <data android:mimeType="application/vnd.android.package-archive" />
        </intent>
    </queries>`;

if (!existsSync(manifestPath)) {
  console.error(`Android project is missing: ${manifestPath}`);
  process.exit(1);
}

let manifest = readFileSync(manifestPath, "utf8");
if (!manifest.includes("android.permission.REQUEST_INSTALL_PACKAGES")) {
  manifest = manifest.replace(
    '    <uses-permission android:name="android.permission.INTERNET" />',
    `    <uses-permission android:name="android.permission.INTERNET" />\n${installPermission}`,
  );
}
if (!manifest.includes("application/vnd.android.package-archive")) {
  manifest = manifest.replace("    <application", `${queries}\n\n    <application`);
}
writeFileSync(manifestPath, manifest);

if (existsSync(pathsFile)) {
  let paths = readFileSync(pathsFile, "utf8");
  if (!paths.includes('name="updates"')) {
    paths = paths.replace(
      "</paths>",
      '  <cache-path name="updates" path="." />\n</paths>',
    );
    writeFileSync(pathsFile, paths);
  }
}

// Tauri derives the Gradle working directory from the Cargo workspace root, so the
// rustBuild task runs the CLI at the repo root and resolves src-tauri/tauri.conf.json.
// Point it at the mobile crate so the CLI reads the address file the outer build wrote.
if (!existsSync(appGradlePath)) {
  console.error(`Android Gradle module is missing: ${appGradlePath}`);
  process.exit(1);
}
const rootDirRel = relative(appModuleDir, mobileDir).split(sep).join("/");
let appGradle = readFileSync(appGradlePath, "utf8");
if (!/rootDirRel = "[^"]*"/.test(appGradle)) {
  console.error(`Could not find rootDirRel in ${appGradlePath}`);
  process.exit(1);
}
appGradle = appGradle.replace(/rootDirRel = "[^"]*"/, `rootDirRel = "${rootDirRel}"`);
writeFileSync(appGradlePath, appGradle);

console.log("patched Android install permission and Gradle working directory");
