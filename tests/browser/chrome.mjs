import assert from "node:assert/strict";
import { waitForChromePort } from "./chrome-startup.mjs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  accessSync,
  constants,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as pause } from "node:timers/promises";

const assetRoot = realpathSync(
  fileURLToPath(new URL("../../assets", import.meta.url)),
);
const fixtures = new Set([
 ...["empty","pending","other-owner","reader","site","expired","withdrawn","approved","focused","paged","review","burn-review","incompatible","review-expired","review-withdrawn","review-approved","derived"].map(state=>"windows-source-"+state),
 ...["install","remove","empty","pending","delivered","observed","drifted","unknown","waiting","unavailable","cancelled","expired","reader","paged"].map(state=>"windows-check-"+state),
 ...["install","remove","pending","delivered","observed","restart","uncertain","reader","cancelled","expired","failed","not-started"].map(state=>"windows-dispatch-"+state),
  "profiles",
  "wifi-eap-profiles",
  "wifi-eap-reader",
  "ikev2-profiles",
  "ikev2-reader",
  "desktop-inventory",
  "desktop-inventory-partial",
	...["approve-winget","approve-msi","approve-exe","detail-winget","detail-msi","detail-exe","reader","withdrawn","catalog"].map(state=>"windows-software-"+state),
 ...["prepared","reader","cancelled","expired","withdrawn","empty"].map(state=>"windows-requests-"+state),
  ...["viewer", "operator"].flatMap(role =>
    ["first", "next", "empty", "long"].map(state => "desktop-software-" + state + "-" + role),
  ),
  ...["viewer", "operator"].flatMap(role =>
    ["new", "queued", "pending", "accepted", "stopped", "unconfirmed"].map(
      state => "desktop-refresh-" + state + "-" + role,
    ),
  ),
]);
const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css",
  ".js": "text/javascript",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

function chromeExecutable() {
  assert(
    ["darwin", "linux"].includes(process.platform),
    "The browser runner supports macOS and Linux",
  );
  const candidates = process.env.CHROME_BIN
    ? [process.env.CHROME_BIN]
    : [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
      ];
  const executable = candidates.find((path) => existsSync(path));
  assert(
    executable,
    "Set CHROME_BIN to an installed Chrome or Chromium executable",
  );
  accessSync(executable, constants.X_OK);
  return executable;
}

// Only this disposable server and browser are owned by the test. No console,
// database, issuer or device is contacted, and no form mutation is served.
export async function withChrome({ fixtureRoot, artifactRoot }, run) {
  const executable = chromeExecutable();
  const root = realpathSync(fixtureRoot);
  for (const name of fixtures)
    accessSync(join(root, name + ".html"), constants.R_OK);
  const errors = [];
  const server = createServer((req, res) => {
    try {
      assert(req.method === "GET", "Unexpected fixture request method");
      const pathname = new URL(req.url, "http://localhost").pathname;
      if (pathname === "/favicon.ico") {
        res.writeHead(204);
        res.end();
        return;
      }
      let file;
      if (pathname.startsWith("/assets/")) {
        file = realpathSync(
          resolve(assetRoot, decodeURIComponent(pathname.slice(8))),
        );
        assert(file.startsWith(assetRoot + sep), "Asset path escaped its root");
      } else {
        assert(
          fixtures.has(pathname.slice(1, -5)) && pathname.endsWith(".html"),
          "Unexpected fixture path",
        );
        file = realpathSync(join(root, pathname.slice(1)));
        assert(file.startsWith(root + sep), "Fixture path escaped its root");
      }
      res.setHeader(
        "Content-Type",
        types[extname(file)] || "application/octet-stream",
      );
      res.setHeader("Cache-Control", "no-store");
      res.end(readFileSync(file));
    } catch {
      errors.push(
        "A browser request did not match a readable fixture or asset",
      );
      res.writeHead(404);
      res.end();
    }
  });
  const profile = mkdtempSync(join(tmpdir(), "openuem-browser-test-"));
  let chrome,
    ws,
    chromeExit,
    lastPage = "",
    stopping = false;
  let next = 0;
  const pending = new Map();
  const listeners = new Map();
  const abort = new AbortController();
  const interrupt = () =>
    abort.abort(new Error("Browser regression interrupted"));
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  const deadline = setTimeout(
    () => abort.abort(new Error("Browser regression exceeded three minutes")),
    180000,
  );
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        reject(new Error("Browser connection is closed"));
        return;
      }
      const id = ++next;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("CDP timeout: " + method));
      }, 10000);
      pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      ws.send(JSON.stringify({ id, method, params }));
    });
  const rejectPending = (error) => {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
    for (const listener of listeners.values()) listener.reject(error);
    listeners.clear();
  };
  const event = (method) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        listeners.delete(method);
        reject(new Error("Browser event timeout: " + method));
      }, 15000);
      listeners.set(method, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const origin = "http://127.0.0.1:" + server.address().port;
    chrome = spawn(
      executable,
      [
        "--headless=new",
        "--disable-background-networking",
        "--disable-extensions",
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-port=0",
        "--remote-debugging-address=127.0.0.1",
        "--user-data-dir=" + profile,
        "about:blank",
      ],
      { stdio: ["ignore", "ignore", "pipe"], detached: true },
    );
    chromeExit = new Promise((resolve) => {
      chrome.once("exit", resolve);
      chrome.once("error", resolve);
    });
    const port = await waitForChromePort(chrome, profile, abort.signal, artifactRoot);
    const response = await fetch("http://127.0.0.1:" + port + "/json/list", {
      signal: AbortSignal.any([abort.signal, AbortSignal.timeout(10000)]),
    });
    assert(response.ok, "Chrome debugging endpoint failed");
    const pages = await response.json();
    const page = pages.find((page) => page.type === "page");
    assert(page, "Chrome did not create a page");
    ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("Browser connection timeout")),
        10000,
      );
      ws.onopen = () => {
        clearTimeout(timer);
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error("Browser connection failed"));
      };
    });
    ws.onclose = () => rejectPending(new Error("Browser connection closed"));
    ws.onerror = () => rejectPending(new Error("Browser connection failed"));
    ws.onmessage = ({ data }) => {
      const message = JSON.parse(data);
      if (message.id) {
        const request = pending.get(message.id);
        pending.delete(message.id);
        if (request)
          message.error
            ? request.reject(new Error(JSON.stringify(message.error)))
            : request.resolve(message.result);
      } else {
        listeners.get(message.method)?.resolve(message.params);
        listeners.delete(message.method);
        if (message.method === "Runtime.exceptionThrown")
          errors.push(
            "Uncaught page exception: " + message.params.exceptionDetails.text,
          );
        if (message.method === "Fetch.requestPaused") {
          const request = message.params.request;
          const allowed =
            request.method === "GET" && new URL(request.url).origin === origin;
          if (!allowed)
            errors.push(
              "Blocked a request outside the read-only fixture origin",
            );
          send(allowed ? "Fetch.continueRequest" : "Fetch.failRequest", {
            requestId: message.params.requestId,
            ...(!allowed && { errorReason: "BlockedByClient" }),
          }).catch((error) => {
            if (!stopping) errors.push(error.message);
          });
        }
      }
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    const evaluate = async (expression) => {
      const result = await send("Runtime.evaluate", {
        expression,
        returnByValue: true,
        awaitPromise: true,
      });
      assert(
        !result.exceptionDetails,
        "Browser evaluation failed: " + JSON.stringify(result.exceptionDetails),
      );
      return result.result.value;
    };
    const press = async (key, code, keyCode, text) => {
      await send("Input.dispatchKeyEvent", {
        type: "keyDown",
        key,
        code,
        windowsVirtualKeyCode: keyCode,
        text,
      });
      await send("Input.dispatchKeyEvent", {
        type: "keyUp",
        key,
        code,
        windowsVirtualKeyCode: keyCode,
      });
    };
    const capture = async (name) => {
      assert(/^[a-z0-9-]+$/.test(name), "Invalid screenshot name");
      const shot = await send("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: false,
      });
      writeFileSync(
        join(artifactRoot, name + ".png"),
        Buffer.from(shot.data, "base64"),
      );
    };
    const browser = {
      evaluate,
      capture,
      check: assert,
      enter: () => press("Enter", "Enter", 13, "\r"),
      space: () => press(" ", "Space", 32, " "),
      version: await send("Browser.getVersion"),
      assertHealthy: () =>
        assert.deepEqual(errors, [], "Browser errors on " + lastPage),
      visit: async (file, width) => {
        assert(fixtures.has(file), "Unknown fixture");
        lastPage = file + " at " + width + "px";
        await send("Emulation.setDeviceMetricsOverride", {
          width,
          height: 1000,
          deviceScaleFactor: 1,
          mobile: false,
        });
        const [navigation] = await Promise.all([
          send("Page.navigate", { url: origin + "/" + file + ".html" }),
          event("Page.loadEventFired"),
        ]);
        assert(!navigation.errorText, "Fixture navigation failed");
        await evaluate(
          "document.fonts.ready.then(() => new Promise(requestAnimationFrame))",
        );
        browser.assertHealthy();
      },
    };
    const interrupted = new Promise((_, reject) => {
      if (abort.signal.aborted) reject(abort.signal.reason);
      else
        abort.signal.addEventListener(
          "abort",
          () => reject(abort.signal.reason),
          { once: true },
        );
    });
    try {
      await Promise.race([run(browser), interrupted]);
      browser.assertHealthy();
    } catch (error) {
      await capture("failure").catch(() => {});
      throw new Error(lastPage + ": " + error.message, { cause: error });
    }
  } finally {
    stopping = true;
    clearTimeout(deadline);
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", interrupt);
    rejectPending(new Error("Browser test finished"));
    ws?.close();
    if (chrome?.pid) {
      try {
        process.kill(-chrome.pid, "SIGTERM");
      } catch {}
      await Promise.race([chromeExit, pause(3000)]);
      try {
        process.kill(-chrome.pid, "SIGKILL");
      } catch {}
    }
    rmSync(profile, { recursive: true, force: true });
    server.closeAllConnections();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }
}
