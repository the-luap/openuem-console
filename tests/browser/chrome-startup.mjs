import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as pause } from "node:timers/promises";

// Observe one already-spawned, owned browser. A delayed or partially written
// port file must not trigger a second browser or a weaker sandbox configuration.
export async function waitForChromePort(
  chrome,
  profile,
  signal,
  artifactRoot,
  { timeoutMs = 45000, pollMs = 100 } = {},
) {
  const started = performance.now();
  let stderr = "", startupError, port, outcome = "failed";
  const receive = (data) => { stderr = (stderr + data.toString()).slice(-8192); };
  const fail = (error) => { startupError = error; };
  chrome.stderr.on("data", receive);
  chrome.once("error", fail);
  try {
    while (performance.now() - started < timeoutMs) {
      signal.throwIfAborted();
      if (startupError) throw startupError;
      if (chrome.exitCode !== null || chrome.signalCode !== null)
        throw new Error("Chrome exited during startup: " + stderr);
      let candidate;
      try {
        candidate = readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n")[0];
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const number = Number(candidate);
      if (/^[1-9]\d{0,4}$/.test(candidate) && number <= 65535) {
        port = number;
        outcome = "ready";
        return port;
      }
      await pause(Math.min(pollMs, Math.max(1, timeoutMs - (performance.now() - started))), undefined, { signal });
    }
    throw new Error("Chrome did not expose a valid debugging port within " + timeoutMs + "ms: " + stderr);
  } finally {
    chrome.stderr.off("data", receive);
    chrome.off("error", fail);
    writeFileSync(join(artifactRoot, "chrome-startup.json"), JSON.stringify({
      outcome, elapsedMs: Math.round(performance.now() - started), port,
      exitCode: chrome.exitCode, signalCode: chrome.signalCode, stderr,
    }, null, 2) + "\n");
  }
}
