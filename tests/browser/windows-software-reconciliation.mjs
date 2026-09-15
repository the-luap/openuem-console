export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const state of ["install", "remove", "empty", "pending", "delivered", "observed", "drifted", "unknown", "waiting", "unavailable", "cancelled", "expired", "reader", "paged"]) {
    for (const width of [390, 768, 1440]) {
      await visit("windows-check-" + state, width);
      check(await evaluate("!document.querySelector('main img, main iframe')"), "Software check data injected markup");
      check(await evaluate("!document.querySelector('main').textContent.includes('system_process_created') && !document.querySelector('main').textContent.includes('original_nonce')"), "Check exposed private boot or nonce evidence");
      if (["install", "remove"].includes(state)) {
        check(await evaluate("document.querySelector('main').textContent.includes('This check does not run or repeat the installer')"), "Read-only review omitted its effect");
        check(await evaluate("!document.querySelector('main input[name=source_url],main input[name=arguments],main input[name=operation]')"), "Read-only review accepted executable parameters");
        await evaluate(`window.f=document.querySelector('main form'); window.submissions=[];
          f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({path:new URL(f.action).pathname,fields:Object.fromEntries(new FormData(f))})},true); f.requestSubmit()`);
        check(await evaluate("submissions.length===0"), "Read-only check omitted confirmation");
        await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");
        await enter();
        const submissions = await evaluate("submissions");
        check(submissions.length === 1 && submissions[0].path === "/tenant/1/software/catalog/90000000-0000-4000-8000-000000000030/windows-requests/90000000-0000-4000-8000-000000000033/dispatch/reconcile", "Check lost its exact original request");
        const fields = submissions[0].fields;
        check(fields.reconciliation_id === "90000000-0000-4000-8000-000000000040" && fields.review_hash === "a".repeat(64) && fields.csrf === "test-csrf-token" && fields.confirmed === "yes" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(fields.expires_at), "Check lost review, deadline or CSRF binding");
      } else {
        const cancellation = await evaluate("!!document.querySelector('main form[action$=cancel]')");
        check(cancellation === (state === "pending"), "Check cancellation escaped delivery or role restrictions");
        const review = await evaluate("!!document.querySelector('main a[href$=reconcile]')");
        check(review === ["empty", "unknown", "waiting", "unavailable", "cancelled", "expired", "paged"].includes(state), "Review ignored an active check or completed release");
        if (state === "reader") check(await evaluate("!document.querySelector('main form')"), "Reader received check mutation controls");
        if (["observed", "drifted"].includes(state)) {
          check(await evaluate("document.querySelector('main').textContent.includes('Original execution remains uncertain') && document.querySelector('main').textContent.includes('This verified observation released the original reservation') && !document.querySelector('main').textContent.includes('another operation is blocked')"), "Release rewrote execution history or retained stale blocking guidance");
        }
        if (state === "paged") check(await evaluate("document.querySelector('main a[href*=before]').getAttribute('href').endsWith('/dispatch/reconciliations?before=90000000-0000-4000-8000-000000000041')"), "History cursor lost original scope");
        if (state === "pending") {
          await evaluate(`window.f=document.querySelector('main form'); window.submissions=[];
            f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push(Object.fromEntries(new FormData(f)))},true); f.requestSubmit()`);
          check(await evaluate("submissions.length===0"), "Check cancellation omitted confirmation");
          await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");
          await enter();
          check(await evaluate("submissions.length===1 && submissions[0].csrf==='test-csrf-token' && submissions[0].confirmed==='yes'"), "Check cancellation lost explicit confirmation");
        }
      }
      check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"), "Software check page overflow");
      if (width === 390 && ["install", "observed", "unknown"].includes(state)) {
        await evaluate("window.scrollTo(0,0)");
        await capture("windows-check-" + state + "-390");
      }
      record({ name: "Windows software check " + state, width, passed: true });
    }
  }
}
