export default async function run(browser, record) {
  for (const state of ["list", "empty", "detail", "archived", "viewer", "long"]) {
    for (const width of [390, 768, 1440]) {
      await browser.visit("device-groups-" + state, width);
      const view = await browser.evaluate(`(() => {
        const root=document.querySelector('main[id^="device-group"]');
        window.groupForm=root.querySelector('form[aria-label="Edit group definition"]');
        const members=root.querySelector('nav[aria-label="Group member pages"]');
        const history=root.querySelector('nav[aria-label="Group history pages"]');
        const list=root.querySelector('nav[aria-label="Device group pages"]');
        window.groupPageLink=(members || list || history).querySelector('a');
        return {form:!!groupForm,method:groupForm?.method,path:groupForm?new URL(groupForm.action).pathname:null,
          revision:groupForm?.elements.revision?.value,archived:groupForm?.elements.archived?.checked,
          rows:root.querySelectorAll('tbody tr').length,scripts:root.querySelectorAll('script').length,
          history:root.querySelector('#group-history')?.textContent,
          links:[...(members?.querySelectorAll('a')||[]),...(history?.querySelectorAll('a')||[])].map(a=>({path:new URL(a.href).pathname,revision:new URL(a.href).searchParams.get('revision')})),
          width:document.documentElement.scrollWidth,viewport:innerWidth};
      })()`);
      const creating = state === "list" || state === "empty";
      browser.check(view.form === (state !== "viewer"), "Group edit controls disagree with permissions");
      browser.check(view.scripts === 0 && view.width <= view.viewport + 1, "Group metadata became script content or overflows the viewport");
      browser.check(view.rows === (creating || state === "archived" ? 0 : 1), "Group preview does not reflect its state");
      browser.check(view.links.every(a => a.path === "/tenant/1/site/1/device-groups/00000000-0000-0000-0000-000000000001" && a.revision === "3"), "Group pages lost scope or definition revision");
      if (!creating) browser.check(view.history.includes("Changed by owned-operator"), "Definition history is absent");
      await browser.evaluate(`window.groupPageActivated=false;groupPageLink.addEventListener('click',e=>{e.preventDefault();window.groupPageActivated=true});groupPageLink.focus()`);
      await browser.enter();
      browser.check(await browser.evaluate("groupPageActivated"), "Group pages cannot be activated by keyboard");
      if (view.form) {
        browser.check(view.method === "post" && view.path === "/tenant/1/site/1/device-groups" + (creating ? "" : "/00000000-0000-0000-0000-000000000001"), "Group write action is not scoped");
        browser.check(creating ? view.revision === undefined : view.revision === "3", "Group edit lost its expected revision");
        browser.check(creating || view.archived === (state === "archived"), "Archive state was not preserved");
        await browser.evaluate(`groupForm.elements.name.value='Owned keyboard group';groupForm.elements.q.value='Owned';groupForm.elements.platform.value='windows';groupForm.addEventListener('submit',e=>{e.preventDefault();window.groupFields=Object.fromEntries(new FormData(groupForm,e.submitter))});groupForm.querySelector('button').focus()`);
        await browser.enter();
        const fields = await browser.evaluate("groupFields");
        browser.check(fields.csrf === "owned-csrf" && fields.name === "Owned keyboard group" && fields.q === "Owned" && fields.platform === "windows", "Keyboard save lost the rule or CSRF token");
      }
      if (width === 390) await browser.capture("device-groups-" + state + "-390");
      record({ name: "Dynamic device groups " + state, width, passed: true });
    }
  }
}
