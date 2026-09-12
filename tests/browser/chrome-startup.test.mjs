import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { waitForChromePort } from "./chrome-startup.mjs";

async function withChild(script, run) {
  const root = mkdtempSync(join(tmpdir(), "openuem-chrome-startup-test-"));
  const child = spawn(process.execPath, ["--input-type=module", "-e", script, root], { stdio: ["ignore", "ignore", "pipe"] });
  const exited = new Promise((resolve) => child.once("exit", resolve));
  try { await run(child, root); }
  finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await exited;
    rmSync(root, { recursive: true, force: true });
  }
}

const writer = `import {writeFileSync} from 'node:fs'; import {join} from 'node:path'; const file=join(process.argv[1],'DevToolsActivePort');`;

test("delayed and partial port files continue observing the same child", async () => {
  await withChild(writer + `writeFileSync(file,''); setTimeout(()=>writeFileSync(file,'70000\\n'),60); setTimeout(()=>writeFileSync(file,'34567\\n/devtools/browser/synthetic'),120); setInterval(()=>{},1000);`, async (child, root) => {
    const port = await waitForChromePort(child, root, new AbortController().signal, root, {timeoutMs: 3000, pollMs: 10});
    assert.equal(port, 34567);
    const diagnostic = JSON.parse(readFileSync(join(root, "chrome-startup.json")));
    assert.equal(diagnostic.outcome, "ready");
    assert.equal(diagnostic.exitCode, null);
  });
});

test("an exited browser preserves startup diagnostics", async () => {
  await withChild(`process.stderr.write('synthetic browser startup failure'); process.exitCode=23;`, async (child, root) => {
    await assert.rejects(waitForChromePort(child, root, new AbortController().signal, root, {timeoutMs: 3000, pollMs: 10}), /Chrome exited during startup: synthetic browser startup failure/);
    const diagnostic = JSON.parse(readFileSync(join(root, "chrome-startup.json")));
    assert.equal(diagnostic.exitCode, 23);
    assert.match(diagnostic.stderr, /synthetic browser startup failure/);
  });
});

test("a live child without a port reaches a bounded failure", async () => {
  await withChild(`process.stderr.write('synthetic waiting browser'); setInterval(()=>{},1000);`, async (child, root) => {
    await assert.rejects(waitForChromePort(child, root, new AbortController().signal, root, {timeoutMs: 300, pollMs: 10}), /did not expose a valid debugging port/);
    const diagnostic = JSON.parse(readFileSync(join(root, "chrome-startup.json")));
    assert.equal(diagnostic.outcome, "failed");
    assert.equal(diagnostic.exitCode, null);
    assert.ok(diagnostic.elapsedMs >= 300);
    assert.ok(diagnostic.stderr.length <= 8192);
  });
});

test("an interrupt stops startup observation without waiting for its deadline", async () => {
  await withChild(`setInterval(()=>{},1000);`, async (child, root) => {
    const controller = new AbortController();
    controller.abort(new Error("synthetic startup interrupt"));
    await assert.rejects(waitForChromePort(child, root, controller.signal, root), /synthetic startup interrupt/);
    assert.equal(JSON.parse(readFileSync(join(root, "chrome-startup.json"))).outcome, "failed");
  });
});
