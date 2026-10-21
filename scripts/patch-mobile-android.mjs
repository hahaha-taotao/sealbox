import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = resolve(root, "src-tauri-mobile/gen/android/app/src/main/AndroidManifest.xml");
const pathsFile = resolve(root, "src-tauri-mobile/gen/android/app/src/main/res/xml/file_paths.xml");

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

console.log("patched Android install permission");
