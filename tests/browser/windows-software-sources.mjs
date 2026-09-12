export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  const base = "/tenant/1/software/catalog/90000000-0000-4000-8000-000000000030/sources";
  const source = "90000000-0000-4000-8000-000000000042";
  const approval = "90000000-0000-4000-8000-000000000043";
  for (const state of ["empty", "pending", "other-owner", "reader", "site", "expired", "withdrawn", "approved", "focused", "paged", "review", "burn-review", "incompatible", "review-expired", "review-withdrawn", "review-approved", "derived"]) {
    for (const width of [390, 768, 1440]) {
      await visit("windows-source-" + state, width);
      check(await evaluate("!document.querySelector('main img,main iframe,main input[name=source_url],main input[name=arguments]')"), "Source review injected markup or executable parameters");
      const captureForm = ["empty", "pending", "other-owner", "expired", "approved", "paged"].includes(state);
      const approvalForm = ["review", "burn-review"].includes(state);
      check(await evaluate("!!document.querySelector('main input[name=request_id]')") === captureForm, "Source capture ignored role or original withdrawal");
      check(await evaluate("!!document.querySelector('main input[name=approval_id]')") === approvalForm, "Source approval escaped its live compatible review");
      check(await evaluate("[...document.querySelectorAll('main a')].some(a=>a.textContent==='Review installer choices')") === ["pending", "paged"].includes(state), "Installer review escaped ownership or expiry");
      if (captureForm || approvalForm) {
        await evaluate(`window.f=document.querySelector('main form');window.submissions=[];
          f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({path:new URL(f.action).pathname,fields:Object.fromEntries(new FormData(f))})},true);f.requestSubmit()`);
        check(await evaluate("submissions.length===0"), "Source mutation omitted confirmation");
        await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");
        await enter();
        const submissions = await evaluate("submissions");
        check(submissions.length === 1, "Keyboard confirmation failed");
        const { fields, path } = submissions[0];
        check(fields.confirmed === "yes" && fields.csrf === "test-csrf-token", "Source mutation lost confirmation or CSRF");
        if (captureForm) {
          check(path === base && fields.request_id === source && Object.keys(fields).length === 3, "Capture changed approved coordinate or added parameters");
        } else {
          check(path === base + "/" + source + "/approve" && fields.approval_id === approval && fields.installer_index === "0" && fields.review_hash === "d".repeat(64) && Object.keys(fields).length === 5, "Approval changed exact reviewed installer");
          check(await evaluate("document.querySelector('main').textContent.includes('separate installer revision') && document.querySelector('main').textContent.includes('later confirmation')"), "Approval omitted its effect");
          const text = await evaluate("document.querySelector('main').textContent");
          if (state === "burn-review") {
            check(text.includes("Windows · Burn") && text.includes("Required Burn bundle code") && text.includes("{90000000-0000-4000-8000-000000000001}") && text.includes("64-bit machine registration") && !text.includes("Required MSI product code"), "Burn review lost its exact bundle identity");
            check(text.includes("same pinned bundle") && text.includes("Dispatch requires an agent with Burn support"), "Burn review omitted removal or recipient requirements");
          } else {
            check(text.includes("Windows · MSI") && text.includes("Required MSI product code") && !text.includes("Required Burn bundle code"), "MSI review changed its installer kind or detection rule");
          }
        }
      } else {
        check(await evaluate("!document.querySelector('main form')"), "Read-only source state exposed mutation");
      }
      if (state === "paged") check(await evaluate("document.querySelector('main a[href*=before]').getAttribute('href')") === base + "?before=90000000-0000-4000-8000-000000000045", "Source history cursor lost original revision");
      if (state === "site") check(await evaluate("[...document.querySelectorAll('main a')].find(a=>a.textContent==='View source evidence').getAttribute('href')") === base.replace("/tenant/1/", "/tenant/1/site/1/") + "/" + source, "Source evidence lost site scope");
      if (state === "derived") check(await evaluate("[...document.querySelectorAll('main a')].find(a=>a.textContent==='View WinGet source evidence').getAttribute('href')") === base + "/" + source, "Derived revision lost original source provenance");
      check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"), "WinGet source page overflow");
      if (width === 390 && ["pending", "review", "burn-review", "derived"].includes(state)) {
        await evaluate("window.scrollTo(0,0)");
        await capture("windows-source-" + state + "-390");
      }
      record({ name: "WinGet source " + state, width, passed: true });
    }
  }
}
