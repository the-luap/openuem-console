import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { withChrome } from "./chrome.mjs";
import wifi from "./wifi-eap.mjs";
import ad from "./ad-certificates.mjs";
import vpn from "./vpn-ikev2.mjs";
import inventory from "./desktop-inventory.mjs";
import software from "./desktop-software.mjs";
import windowsSoftware from "./windows-software-catalog.mjs";
import windowsRequests from "./windows-software-requests.mjs";
import windowsDispatch from "./windows-software-dispatch.mjs";
import windowsChecks from "./windows-software-reconciliation.mjs";
import windowsSources from "./windows-software-sources.mjs";
import accountLanguage from "./account-language.mjs";
import timestamps from "./timestamps.mjs";
import network from "./desktop-network.mjs";
import scopedNetwork from "./desktop-network-scoped.mjs";

assert(
  process.env.APPLE_MDM_UI_ARTIFACTS,
  "Set APPLE_MDM_UI_ARTIFACTS to the directory rendered by the mdm_views and desktop_views tests",
);
const artifactRoot = process.env.BROWSER_TEST_ARTIFACTS
  ? resolve(process.env.BROWSER_TEST_ARTIFACTS)
  : mkdtempSync(join(tmpdir(), "openuem-browser-results-"));
mkdirSync(artifactRoot, { recursive: true });
const report = {
  startedAt: new Date().toISOString(),
  node: process.version,
  platform: process.platform,
  commit: process.env.GITHUB_SHA,
  passed: false,
  cases: [],
};
try {
  await withChrome(
    { fixtureRoot: process.env.APPLE_MDM_UI_ARTIFACTS, artifactRoot },
    async (browser) => {
      report.browser = browser.version;
      const record = (result) => {
        browser.assertHealthy();
        report.cases.push(result);
        console.log(JSON.stringify(result));
      };
      for (const [suite, count] of [
        [wifi, 39],
        [ad, 15],
        [vpn, 27],
        [inventory, 42],
        [software, 24],
        [windowsSoftware, 27],
        [windowsRequests, 18],
        [windowsDispatch, 36],
        [windowsChecks, 42],
        [windowsSources, 51],
        [network, 12],
        [scopedNetwork, 24],
        [accountLanguage,30],
        [timestamps,21],
      ]) {
        const before = report.cases.length;
        await suite(browser, record);
        assert.equal(
          report.cases.length - before,
          count,
          "The expected browser case matrix did not finish",
        );
      }
    },
  );
  report.passed = true;
} catch (error) {
  report.error = error.message;
  console.error(error);
  process.exitCode = 1;
} finally {
  report.finishedAt = new Date().toISOString();
  writeFileSync(
    join(artifactRoot, "results.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log("Browser artifacts: " + artifactRoot);
}
