// Rendered inventory and refresh forms; keyboard submissions never leave the page.
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const page of ["desktop-inventory", "desktop-inventory-partial", "desktop-inventory-missing-numbers", "desktop-inventory-zero-numbers"])
    for (const width of [390, 768, 1440]) {
      await visit(page, width);
      check(
        await evaluate(`document.querySelector('main').textContent.includes('Computer inventory') &&
          document.querySelector('main').querySelectorAll('form,img,iframe').length === 0 &&
          !!document.querySelector('a[href="/tenant/1/site/1/devices"]')`),
        "Read-only inventory or scoped navigation changed",
      );
      if (page.endsWith("-partial"))
        check(
          await evaluate(`document.querySelector('main').textContent.includes('No hardware report received yet.')`),
          "Incomplete inventory state missing",
        );
      else {
        const fields = await evaluate(`(() => {
          const section=Array.from(document.querySelectorAll('main section')).find(s=>s.querySelector('h2')?.textContent==='Hardware');
          return Object.fromEntries(Array.from(section.querySelectorAll('dt'),dt=>[dt.textContent,dt.nextElementSibling.textContent]));
        })()`);
        const missing=page.endsWith('missing-numbers'), zero=page.endsWith('zero-numbers');
        check(fields.Memory===(missing?'Not reported':zero?'0.0 GiB':'16.0 GiB') && fields['Processor cores']===(missing?'Not reported':zero?'0':'8'),"Missing hardware values and reported zero were conflated");
        check(await evaluate(`document.querySelector('main').textContent.includes('a reported zero does not verify that memory or processor cores are absent')`),"Stored hardware report was presented as verified");
      }
      check(
        await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
        "Inventory page overflow",
      );
      record({ name: page, width, passed: true });
    }

  const labels = {
    queued: "Waiting to send",
    pending: "Delivery not yet confirmed",
    accepted: "Accepted for delivery",
    stopped: "Stopped before delivery",
    unconfirmed: "Delivery could not be confirmed",
  };
  for (const role of ["viewer", "operator"])
    for (const state of ["new", ...Object.keys(labels)])
      for (const width of [390, 768, 1440]) {
        await visit("desktop-refresh-" + state + "-" + role, width);
        const hasForm = role === "operator" && state !== "queued" && state !== "pending";
        const data = await evaluate(`(() => {
          const panel = document.querySelector('#inventory-refresh');
          if (!panel) throw Error('Inventory refresh panel missing');
          return { forms: panel.querySelectorAll('form').length, text: panel.textContent,
            statuses: [...panel.querySelectorAll('[role="status"]')].map(e => e.textContent) };
        })()`);
        check(data.forms === Number(hasForm), "Refresh authority or pending form state changed");
        check(
          data.text.includes("The device must still collect and send its report") &&
            !data.text.includes("Report completed"),
          "Broker acceptance was presented as report completion",
        );
        if (state !== "new")
          check(data.statuses.includes(labels[state]), "Accessible delivery status missing");
        if (hasForm) {
          await evaluate(`
            window.f = document.querySelector('#inventory-refresh form');
            window.posts = [];
            f.addEventListener('submit', e => {
              e.preventDefault(); e.stopImmediatePropagation();
              posts.push({ path: new URL(f.action).pathname, method: f.method,
                data: [...new FormData(f).entries()] });
            }, true);
            f.querySelector('[type="submit"]').focus();
          `);
          await enter();
          const posts = await evaluate("posts");
          check(
            posts.length === 1 && posts[0].method === "post" &&
              posts[0].path === "/tenant/1/site/1/computers/desktop-report/refresh" &&
              posts[0].data.length === 2 &&
              posts[0].data.some(([k, v]) => k === "csrf" && v === "refresh-test-csrf") &&
              posts[0].data.some(([k, v]) => k === "request_id" && v === "10000000-0000-4000-8000-000000000001"),
            "Keyboard refresh lost its scope, CSRF token or replay binding",
          );
        }
        check(
          await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
          "Refresh page overflow",
        );
        if (role === "operator" && width === 390 && ["new", "pending", "accepted"].includes(state)) {
          await evaluate(`document.querySelector('#inventory-refresh').scrollIntoView({block:'start'})`);
          check(
            await evaluate(`document.querySelector('#inventory-refresh').getBoundingClientRect().top >= 150`),
            "Refresh anchor is obscured by the fixed header",
          );
          await capture("desktop-refresh-" + state + "-390");
        }
        record({ name: "Desktop refresh " + role + " " + state, width, passed: true });
      }
}
