export default async function run(browser, record) {
  for (const state of ["first", "next", "empty", "long"]) {
    for (const width of [390, 768, 1440]) {
      await browser.visit("device-list-" + state, width);
      const result = await browser.evaluate(`(() => {
        const root=document.querySelector('#device-management');
        const form=root.querySelector('form');
        const nav=root.querySelector('nav[aria-label="Device list pages"]');
        window.devicePageLinks=[...nav.querySelectorAll('a')];
        return {rows:root.querySelectorAll('tbody tr').length,post:root.querySelectorAll('form[method="post"]').length,
          links:devicePageLinks.map(a=>({text:a.textContent,path:new URL(a.href).pathname,search:new URL(a.href).searchParams.get('q'),platform:new URL(a.href).searchParams.get('platform'),sort:new URL(a.href).searchParams.get('sort'),after:new URL(a.href).searchParams.get('after')})),
          search:form.elements.q.value,platform:form.elements.platform.value,sort:form.elements.sort.value,afterField:!!form.elements.after,
          width:document.documentElement.scrollWidth,viewport:innerWidth,script:root.querySelector('tbody script')!==null};
      })()`);
      browser.check(result.rows === (state === "empty" ? 0 : 25), "Device page row count is incorrect");
      browser.check(result.post === 0 && !result.script, "Device list exposed a mutation or unescaped metadata");
      browser.check(result.search === "Owned" && result.platform === "ipados" && result.sort === "recent" && !result.afterField, "Filtering failed to retain values or reset the page cursor");
      browser.check(result.links.every(a => a.path === "/tenant/1/site/1/devices" && a.search === "Owned" && a.platform === "ipados" && a.sort === "recent"), "Page links lost scope, filters or sorting");
      browser.check(result.links.some(a => a.text === "Next page" && a.after === "owned-page") === (state !== "empty"), "Next page availability is incorrect");
      browser.check(result.links.some(a => a.text === "First page" && a.after === null) === (state !== "first"), "First page availability is incorrect");
      await browser.evaluate(`window.pageActivated=false;devicePageLinks[0].addEventListener('click',e=>{e.preventDefault();window.pageActivated=true});devicePageLinks[0].focus()`);
      await browser.enter();
      browser.check(await browser.evaluate("window.pageActivated"), "Device pagination cannot be activated with the keyboard");
      browser.check(result.width <= result.viewport + 1, "Device list overflows the viewport");
      if (width === 390) await browser.capture("device-list-" + state + "-390");
      record({name: "Device list " + state, width, passed: true});
    }
  }
}
