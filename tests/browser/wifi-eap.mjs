// Synthetic rendered forms only; submissions are captured and prevented.
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, space, capture } = browser;
  for (const scope of ["System", "User"])
    for (const trust of ["existing", "anchors"])
      for (const tls of ["1.2", "range", "1.3"])
        for (const width of [390, 768, 1440]) {
          await visit("wifi-eap-profiles", width);
          await evaluate(
            `
              window.f = document.querySelector('.wifi-eap-profile-editor');
              if (!f) throw Error('Wi-Fi editor missing');
              f.closest('details').open = true;
              window.posts = [];
              f.addEventListener(
                'submit',
                (e) => {
                  e.preventDefault();
                  e.stopImmediatePropagation();
                  posts.push({
                    path: new URL(f.action).pathname,
                    data: Object.fromEntries(new FormData(f)),
                  });
                },
                true,
              );
              window.set = (name, value) => {
                f.elements.namedItem(name).value = value;
                f.elements
                  .namedItem(name)
                  .dispatchEvent(new Event('change', { bubbles: true }));
              };
              f.querySelector('[type="submit"]').focus();
            `,
          );
          check(
            await evaluate(
              `
                f.dataset.initialized === 'true' &&
                  f.elements.trust_revision.value === 'existing' &&
                  f.elements.auto_join.value === 'true' &&
                  f.elements.hidden_network.value === 'false' &&
                  f.elements.tls_minimum.value === '1.2' &&
                  f.elements.tls_maximum.value === '1.2';
              `,
            ),
            "Wi-Fi defaults changed",
          );
          await enter();
          check(
            await evaluate("posts.length===0"),
            "empty Wi-Fi form submitted",
          );
          const identity =
            scope === "System"
              ? "70000000-0000-4000-8000-000000000001/7"
              : "70000000-0000-4000-8000-000000000002/3";
          const anchor =
            scope === "System"
              ? "70000000-0000-4000-8000-000000000003/4"
              : "70000000-0000-4000-8000-000000000004/2";
          await evaluate(
            `
              set('payload_scope', ${JSON.stringify(scope)});
              set('identity_revision', ${JSON.stringify(identity)});
              set('trust_revision', ${JSON.stringify(anchor)});
              f.elements.confirmed.checked = true;
              set('payload_scope', ${JSON.stringify(scope === "System" ? "User" : "System")});
            `,
          );
          check(
            await evaluate(
              `
                f.elements.identity_revision.value === '' &&
                  f.elements.trust_revision.value === '' &&
                  !f.elements.confirmed.checked &&
                  f.elements.trust_revision.required &&
                  !f.elements.trust_revision.checkValidity() &&
                  f
                    .querySelector('[data-certificate-selection-status]')
                    .textContent.includes('cleared');
              `,
            ),
            "scope change silently kept credentials or broadened trust",
          );
          await evaluate(
            `
              set('payload_scope', ${JSON.stringify(scope)});
              set('identity_revision', ${JSON.stringify(identity)});
              set('trust_revision', ${JSON.stringify(trust === "existing" ? "existing" : anchor)});
              set('name', 'Synthetic enterprise Wi-Fi');
              set('identifier', 'com.example.browser-enterprise');
              set('ssid', 'é'.repeat(17));
              set('server_names', 'radius.example.test\\nwpa.*.example.test');
              f.elements.confirmed.checked = true;
              f.querySelector('[type="submit"]').focus();
            `,
          );
          await enter();
          check(
            await evaluate(
              "posts.length===0&&!f.elements.ssid.checkValidity()",
            ),
            "UTF-8 SSID byte limit not enforced",
          );
          await evaluate(
            `
              set('ssid', ' Company café ');
              set('tls_minimum', '1.3');
              set('tls_maximum', '1.2');
              set('outer_identity', 'anonymous@example.test');
              f.querySelector('[type="submit"]').focus();
            `,
          );
          await enter();
          check(
            await evaluate(
              "posts.length===0&&!f.elements.tls_maximum.checkValidity()",
            ),
            "inverted TLS bounds accepted",
          );
          await evaluate(
            `
              set('tls_maximum', '1.3');
              set('outer_identity', '');
              f.querySelector('[type="submit"]').focus();
            `,
          );
          await enter();
          check(
            await evaluate(
              "posts.length===0&&f.elements.outer_identity.required",
            ),
            "TLS 1.3 minimum accepted without outer identity",
          );
          await evaluate(
            `
              set('tls_minimum', ${JSON.stringify(tls === "1.3" ? "1.3" : "1.2")});
              set('tls_maximum', ${JSON.stringify(tls === "1.2" ? "1.2" : "1.3")});
              set('outer_identity', ${JSON.stringify(tls === "1.3" ? "anonymous@example.test" : "")});
              set('auto_join', 'false');
              set('hidden_network', 'true');
              f.elements.confirmed.checked = false;
              window.openUEMWiFiEAP();
              window.openUEMWiFiEAP();
              f.querySelector('[type="submit"]').focus();
            `,
          );
          await enter();
          check(await evaluate("posts.length===0"), "Wi-Fi review omitted");
          check(
            await evaluate(
              `
                Array.from(f.elements.identity_revision.options)
                  .filter((o) => o.dataset.scope)
                  .every(
                    (o) =>
                      o.disabled === (o.dataset.scope !== f.elements.payload_scope.value) &&
                      o.hidden === o.disabled,
                  );
              `,
            ),
            "identity scope options exposed incorrectly",
          );
          await evaluate("f.elements.confirmed.focus()");
          await space();
          await evaluate(`f.querySelector('[type="submit"]').focus()`);
          await enter();
          const posts = await evaluate("posts");
          check(
            posts.length === 1 &&
              posts[0].path === "/tenant/1/ios/configurations",
            "Wi-Fi scoped keyboard submission failed",
          );
          const p = posts[0].data;
          check(
            p.editor === "wifi-eap-tls" &&
              p.csrf === "test-csrf-token" &&
              p.confirmed === "yes" &&
              p.payload_scope === scope &&
              p.identity_revision === identity &&
              p.trust_revision ===
                (trust === "existing" ? "existing" : anchor) &&
              p.ssid === " Company café " &&
              p.auto_join === "false" &&
              p.hidden_network === "true" &&
              p.server_names.split("\n").length === 2,
            "Wi-Fi exact revision, trust, scope, SSID or booleans changed",
          );
          check(
            p.tls_minimum === (tls === "1.3" ? "1.3" : "1.2") &&
              p.tls_maximum === (tls === "1.2" ? "1.2" : "1.3") &&
              p.outer_identity ===
                (tls === "1.3" ? "anonymous@example.test" : ""),
            "Wi-Fi TLS range changed",
          );
          check(
            await evaluate(
              `
                f.textContent.includes('Source updates and deletion do not change') &&
                  f.textContent.includes('PKCS12 copies retain') &&
                  f.textContent.includes('one enrollment') &&
                  f.textContent.includes('iOS/iPadOS 17 or macOS 14');
              `,
            ),
            "Wi-Fi copy and target guidance missing",
          );
          check(
            await evaluate(
              "document.documentElement.scrollWidth<=innerWidth+1",
            ),
            "Wi-Fi page overflow " + scope + " " + width,
          );
          if (
            width === 390 &&
            scope === "User" &&
            trust === "anchors" &&
            tls === "1.3"
          ) {
            await evaluate(
              `
                f.scrollIntoView({ block: 'start' });
                window.scrollBy(0, -120);
              `,
            );
            await capture("wifi-eap-390");
          }
          await evaluate(`
                           f.reset();
                           new Promise((r) => queueMicrotask(r));
                         `);
          check(
            await evaluate(
              `
                f.elements.payload_scope.value === 'System' &&
                  f.elements.trust_revision.value === 'existing' &&
                  !f.elements.outer_identity.required &&
                  !f.elements.confirmed.checked;
              `,
            ),
            "form reset left stale TLS or scope state",
          );
          record({
            name: "EAP-TLS " + scope + " " + trust + " " + tls,
            width,
            passed: true,
          });
        }
  for (const width of [390, 768, 1440]) {
    await visit("wifi-eap-reader", width);
    check(
      await evaluate(
        `
          !document.querySelector('.wifi-eap-profile-editor') &&
            document.body.textContent.includes('Device <identity>');
        `,
      ),
      "reader controls or metadata incorrect",
    );
    check(
      await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),
      "reader profile page overflow",
    );
    record({ name: "EAP-TLS reader", width, passed: true });
  }
}
