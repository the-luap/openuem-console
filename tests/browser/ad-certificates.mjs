// Synthetic rendered forms only; submissions are captured and prevented.
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, space, capture } = browser;
  for (const scope of ["System", "User"])
    for (const variant of ["minimal", "advanced"])
      for (const width of [390, 768, 1440]) {
        await visit("profiles", width);
        await evaluate(
          `
            window.f = document.querySelector('.ad-certificate-editor');
            if (!f) throw Error('AD certificate editor missing');
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
                f.elements.auto_renewal.value === '' &&
                f.elements.key_size.value === '' &&
                f.elements.key_extractable.value === '' &&
                f.elements.all_apps_access.value === '' &&
                !f.elements.namedItem('prompt_for_credentials');
            `,
          ),
          "AD defaults or manual credential control changed",
        );
        await enter();
        check(await evaluate("posts.length===0"), "empty AD form submitted");
        await evaluate(
          `
            set('auto_renewal', 'true');
            f.elements.confirmed.checked = true;
            set('payload_scope', 'User');
          `,
        );
        check(
          await evaluate(
            `
              f.elements.auto_renewal.value === '' &&
                !f.elements.confirmed.checked &&
                Array.from(f.elements.auto_renewal.options).find((o) => o.value === 'true')
                  .disabled &&
                f.querySelector('[data-ad-scope-status]').textContent.includes('cleared');
            `,
          ),
          "User scope retained enabled AD renewal or approval",
        );
        await evaluate(
          `
            set('payload_scope', ${JSON.stringify(scope)});
            set('name', 'Synthetic AD certificate');
            set('identifier', 'com.example.browser-ad');
            set('certificate_server', 'CA.example.test.');
            set('certificate_template', ${JSON.stringify(scope === "System" ? "Machine" : "User")});
            set('renewal_notice', '3651');
            f.elements.confirmed.checked = true;
            f.querySelector('[type="submit"]').focus();
          `,
        );
        await enter();
        check(
          await evaluate(
            "posts.length===0&&!f.elements.renewal_notice.checkValidity()",
          ),
          "AD notification bound not enforced",
        );
        await evaluate(
          `
            set('renewal_notice', '0.5');
            f.querySelector('[type="submit"]').focus();
          `,
        );
        await enter();
        check(
          await evaluate("posts.length===0"),
          "fractional AD notification accepted",
        );
        await evaluate(
          `
            set('renewal_notice', '');
            f.elements.confirmed.checked = false;
            f.querySelector('[type="submit"]').focus();
          `,
        );
        await enter();
        check(await evaluate("posts.length===0"), "AD review omitted");
        if (variant === "advanced")
          await evaluate(
            `
              set('description', 'Certificate <identity>');
              set(
                'certificate_authority',
                'CN=Company CA,CN=Configuration,DC=example,DC=test',
              );
              set('acquisition', 'HTTP');
              set('renewal_notice', '0');
              set('key_size', '3072');
              set('key_extractable', 'false');
              set('all_apps_access', 'false');
              set('auto_renewal', ${JSON.stringify(scope === "System" ? "true" : "false")});
            `,
          );
        await evaluate(
          "window.openUEMADCertificates();window.openUEMADCertificates();f.elements.confirmed.focus()",
        );
        await space();
        await evaluate(`f.querySelector('[type="submit"]').focus()`);
        await enter();
        const posts = await evaluate("posts");
        check(
          posts.length === 1 &&
            posts[0].path === "/tenant/1/ios/configurations",
          "AD scoped keyboard submission failed",
        );
        const p = posts[0].data;
        check(
          p.editor === "apple-ad-certificate" &&
            p.csrf === "test-csrf-token" &&
            p.confirmed === "yes" &&
            p.payload_scope === scope &&
            p.certificate_server === "CA.example.test." &&
            p.certificate_template ===
              (scope === "System" ? "Machine" : "User"),
          "AD scope or server/template data changed",
        );
        if (variant === "advanced")
          check(
            p.acquisition === "HTTP" &&
              p.renewal_notice === "0" &&
              p.key_size === "3072" &&
              p.key_extractable === "false" &&
              p.all_apps_access === "false" &&
              p.auto_renewal === (scope === "System" ? "true" : "false"),
            "AD explicit zero/false/integer data changed",
          );
        else
          check(
            [
              "acquisition",
              "renewal_notice",
              "key_size",
              "key_extractable",
              "all_apps_access",
              "auto_renewal",
            ].every((k) => p[k] === ""),
            "AD optional defaults changed",
          );
        check(
          await evaluate(
            `
              f.textContent.includes('10.13.4') &&
                f.textContent.includes('CA template must support') &&
                f.textContent.includes('manually downloaded user certificates') &&
                f.textContent.includes('does not prove issuance or renewal');
            `,
          ),
          "AD prerequisite guidance missing",
        );
        check(
          await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),
          "AD page overflow " + scope + " " + width,
        );
        if (scope === "User" && variant === "advanced" && width === 390) {
          await evaluate(
            `
              f.scrollIntoView({ block: 'start' });
              window.scrollBy(0, -150);
            `,
          );
          await capture("ad-certificates-390");
        }
        await evaluate(`
                         f.reset();
                         new Promise((r) => queueMicrotask(r));
                       `);
        check(
          await evaluate(
            `
              f.elements.payload_scope.value === 'System' &&
                f.elements.auto_renewal.value === '' &&
                !f.elements.confirmed.checked &&
                !Array.from(f.elements.auto_renewal.options).find((o) => o.value === 'true')
                  .disabled;
            `,
          ),
          "AD reset left stale scope rules",
        );
        record({
          name: "AD certificate " + scope + " " + variant,
          width,
          passed: true,
        });
      }
  for (const width of [390, 768, 1440]) {
    await visit("wifi-eap-reader", width);
    check(
      await evaluate(`!document.querySelector('.ad-certificate-editor')`),
      "reader sees AD controls",
    );
    check(
      await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),
      "AD reader page overflow",
    );
    record({ name: "AD certificate reader", width, passed: true });
  }
}
