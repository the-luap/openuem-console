// Synthetic rendered forms only; submissions are captured and prevented.
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, space, capture } = browser;
  for (const scope of ["System", "User"])
    for (const mode of ["machine", "eap-tls"])
      for (const trust of ["existing", "anchors"])
        for (const width of [390, 768, 1440]) {
          await visit("ikev2-profiles", width);
          await evaluate(
            `
              window.f = document.querySelector('.ikev2-certificate-editor');
              if (!f) throw Error('IKEv2 editor missing');
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
                  f.elements.authentication_mode.value === 'machine' &&
                  f.elements.certificate_type.value === '';
              `,
            ),
            "IKEv2 defaults changed",
          );
          await enter();
          check(
            await evaluate("posts.length===0"),
            "empty IKEv2 form submitted",
          );
          await evaluate(
            `
              set('payload_scope', 'User');
              set('identity_revision', '70000000-0000-4000-8000-000000000002/3');
              set('trust_revision', '70000000-0000-4000-8000-000000000004/2');
              set('certificate_type', 'ECDSA384');
              f.elements.confirmed.checked = true;
              set('payload_scope', 'System');
            `,
          );
          check(
            await evaluate(
              `
                f.elements.identity_revision.value === '' &&
                  f.elements.trust_revision.value === '' &&
                  !f.elements.confirmed.checked &&
                  f.elements.trust_revision.required &&
                  !f.elements.trust_revision.checkValidity();
              `,
            ),
            "IKEv2 scope change silently kept credentials or broadened trust",
          );
          await evaluate(
            `
              f.elements.confirmed.checked = true;
              set('identity_revision', '70000000-0000-4000-8000-000000000001/7');
            `,
          );
          check(
            await evaluate(
              `
                f.elements.certificate_type.value === '' &&
                  !f.elements.confirmed.checked &&
                  Array.from(f.elements.certificate_type.options)
                    .filter((o) => o.value.startsWith('ECDSA'))
                    .every((o) => o.disabled && o.hidden);
              `,
            ),
            "SCEP selection did not clear and disable EC algorithms",
          );
          const identity =
            scope === "System"
              ? "70000000-0000-4000-8000-000000000001/7"
              : "70000000-0000-4000-8000-000000000002/3";
          const anchor =
            scope === "System"
              ? "70000000-0000-4000-8000-000000000003/4"
              : "70000000-0000-4000-8000-000000000004/2";
          const algorithm = scope === "System" ? "RSA" : "ECDSA384";
          await evaluate(
            `
              set('payload_scope', ${JSON.stringify(scope)});
              set('identity_revision', ${JSON.stringify(identity)});
              set('trust_revision', ${JSON.stringify(trust === "existing" ? "existing" : anchor)});
              set('name', 'Synthetic certificate VPN');
              set('identifier', 'com.example.browser-vpn');
              set('connection_name', 'Company VPN');
              set('remote_address', 'vpn.example.test');
              set('local_identifier', 'device.example.test');
              set('remote_identifier', 'vpn.example.test');
              set('authentication_mode', ${JSON.stringify(mode)});
              set('server_issuer', 'Synthetic issuer');
              set('server_name', ${JSON.stringify(mode === "eap-tls" ? "vpn-certificate.example.test" : "")});
              f.elements.confirmed.checked = true;
              f.querySelector('[type="submit"]').focus();
            `,
          );
          await enter();
          check(
            await evaluate(
              "posts.length===0&&!f.elements.certificate_type.checkValidity()",
            ),
            "IKEv2 algorithm choice was implicit",
          );
          await evaluate(
            `
              set('certificate_type', ${JSON.stringify(algorithm)});
              f.elements.confirmed.checked = false;
              window.openUEMIKEv2();
              window.openUEMIKEv2();
              f.querySelector('[type="submit"]').focus();
            `,
          );
          await enter();
          check(await evaluate("posts.length===0"), "IKEv2 review omitted");
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
            "IKEv2 identity scope options exposed incorrectly",
          );
          check(
            await evaluate(
              `
                f.querySelector('[data-ikev2-version-status]').textContent.includes(
                  ${JSON.stringify(mode === "eap-tls" ? "TLS 1.2" : "Machine certificate")},
                );
              `,
            ),
            "IKEv2 authentication guidance stale",
          );
          await evaluate("f.elements.confirmed.focus()");
          await space();
          await evaluate(`f.querySelector('[type="submit"]').focus()`);
          await enter();
          const posts = await evaluate("posts");
          check(
            posts.length === 1 &&
              posts[0].path === "/tenant/1/ios/configurations",
            "IKEv2 scoped keyboard submission failed",
          );
          const p = posts[0].data;
          check(
            p.editor === "vpn-ikev2-certificate" &&
              p.csrf === "test-csrf-token" &&
              p.confirmed === "yes" &&
              p.payload_scope === scope &&
              p.identity_revision === identity &&
              p.trust_revision ===
                (trust === "existing" ? "existing" : anchor) &&
              p.authentication_mode === mode &&
              p.certificate_type === algorithm &&
              p.connection_name === "Company VPN" &&
              p.server_issuer === "Synthetic issuer",
            "IKEv2 revision, trust, scope, mode or algorithm changed",
          );
          check(
            p.server_name ===
              (mode === "eap-tls" ? "vpn-certificate.example.test" : "") &&
              p.local_identifier === "device.example.test" &&
              p.remote_identifier === "vpn.example.test" &&
              p.remote_address === "vpn.example.test",
            "IKEv2 server identity fields changed",
          );
          check(
            await evaluate(
              `
                f.textContent.includes('Source updates and deletion do not change') &&
                  f.textContent.includes('PKCS12 copies retain') &&
                  f.textContent.includes('one enrollment') &&
                  f.textContent.includes('does not establish trust');
              `,
            ),
            "IKEv2 copy and trust guidance missing",
          );
          check(
            await evaluate(
              "document.documentElement.scrollWidth<=innerWidth+1",
            ),
            "IKEv2 page overflow " + scope + " " + width,
          );
          if (
            width === 390 &&
            scope === "User" &&
            trust === "anchors" &&
            mode === "eap-tls"
          ) {
            await evaluate(
              `
                f.elements.identity_revision.scrollIntoView({ block: 'start' });
                window.scrollBy(0, -140);
              `,
            );
            await capture("vpn-ikev2-390");
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
                  f.elements.authentication_mode.value === 'machine' &&
                  f.elements.identity_revision.value === '' &&
                  f.elements.certificate_type.value === '' &&
                  !f.elements.confirmed.checked &&
                  f
                    .querySelector('[data-ikev2-version-status]')
                    .textContent.includes('Machine certificate');
              `,
            ),
            "IKEv2 reset left stale selections or mode",
          );
          record({
            name: "IKEv2 " + scope + " " + mode + " " + trust,
            width,
            passed: true,
          });
        }
  for (const width of [390, 768, 1440]) {
    await visit("ikev2-reader", width);
    check(
      await evaluate(
        `
          !document.querySelector('.ikev2-certificate-editor') &&
            document.body.textContent.includes('Device <identity>');
        `,
      ),
      "IKEv2 reader controls or metadata incorrect",
    );
    check(
      await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),
      "IKEv2 reader page overflow",
    );
    record({ name: "IKEv2 reader", width, passed: true });
  }
}
