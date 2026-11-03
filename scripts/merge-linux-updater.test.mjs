import test from "node:test";
import assert from "node:assert/strict";
import { mergeLinuxUpdater } from "./merge-linux-updater.mjs";

const signature = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZQplZg==";
const url = "https://github.com/hahaha-taotao/sealbox/releases/download/v0.14.6/Sealbox_0.14.6_amd64.AppImage.tar.gz";

test("keeps the windows updater entry and adds linux-x86_64", () => {
  const merged = mergeLinuxUpdater(
    {
      version: "0.14.6",
      platforms: {
        "windows-x86_64": { signature: "win", url: "https://github.com/hahaha-taotao/sealbox/releases/download/v0.14.6/setup.exe" },
      },
    },
    { signature: `  ${signature}\n`, url },
  );
  assert.equal(merged.version, "0.14.6");
  assert.equal(merged.platforms["windows-x86_64"].signature, "win");
  assert.deepEqual(merged.platforms["linux-x86_64"], { signature, url });
});

test("refuses to write when windows is missing or the url is not a release asset", () => {
  assert.throws(() => mergeLinuxUpdater({ platforms: {} }, { signature, url }), /Windows/);
  assert.throws(
    () => mergeLinuxUpdater({ platforms: { "windows-x86_64": { signature: "win", url: "x" } } }, { signature, url: "https://example.com/app.tar.gz" }),
    /GitHub Release/,
  );
});
