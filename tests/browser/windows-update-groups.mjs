export default async function run(browser, record) {
  const groupID = "20000000-0000-4000-8000-000000000001";
  for (const state of ["choose", "empty", "form", "preview", "history", "long"]) {
    for (const width of [390, 768, 1440]) {
      await browser.visit("windows-group-" + state, width);
      const view = await browser.evaluate(`(() => {
        const root=document.querySelector('main.windows-management');
        window.groupActionForm=root.querySelector('form');
        return {width:document.documentElement.scrollWidth,viewport:innerWidth,scripts:root.querySelectorAll('script').length,
          source:root.querySelector('[data-group-source]')?.textContent,
          exclusions:root.querySelector('[data-group-exclusions]')?.textContent,
          choices:[...root.querySelectorAll('a')].filter(a=>a.textContent==='Use this group revision').map(a=>({path:new URL(a.href).pathname,id:new URL(a.href).searchParams.get('group'),revision:new URL(a.href).searchParams.get('group_revision')})),
          method:groupActionForm?.method,path:groupActionForm?new URL(groupActionForm.action).pathname:null,
          readonly:groupActionForm?.querySelector('textarea[name="devices"]')?.readOnly,
          group:groupActionForm?.elements.group_id?.value,revision:groupActionForm?.elements.group_revision?.value};
      })()`);
      browser.check(view.width <= view.viewport + 1 && view.scripts === 0, "Group assignment metadata overflows or became script content");
      const chooser = state === "choose" || state === "empty";
      if (chooser) {
        browser.check(view.choices.length === (state === "empty" ? 0 : 1), "Archived groups became selectable or the empty page has targets");
        browser.check(view.choices.every(a => a.id === groupID && a.revision === "3" && a.path.endsWith("/assign")), "Group choice lost its exact source revision");
        await browser.evaluate(`window.groupChoiceActivated=false;window.choice=[...document.querySelectorAll('main.windows-management a')].find(a=>a.textContent==='Use this group revision') || document.querySelector('nav[aria-label="Device group pages"] a');choice.addEventListener('click',e=>{e.preventDefault();window.groupChoiceActivated=true});choice.focus()`);
        await browser.enter();
        browser.check(await browser.evaluate("groupChoiceActivated"), "Group choice cannot be activated by keyboard");
      } else {
        browser.check(view.source.includes("Revision 3"), "Protected original group source is missing");
        if (state !== "history") {
          browser.check(view.exclusions.includes("Owned <excluded agent>") && view.group === groupID && view.revision === "3", "Group review lost exclusions or its hidden source fields");
          browser.check(view.method === "post" && view.path.endsWith(state === "form" ? "/assign/preview" : "/assign/create"), "Group assignment uses the wrong action");
          if (state === "form") browser.check(view.readonly, "Group target IDs can be edited independently of their source");
          await browser.evaluate(`window.groupSubmitted=false;groupActionForm.addEventListener('submit',e=>{e.preventDefault();window.groupSubmitted=true;window.groupSubmittedFields=Object.fromEntries(new FormData(groupActionForm,e.submitter))});groupActionForm.querySelector('button').focus()`);
          if (state !== "form") {
            await browser.enter();
            browser.check(!(await browser.evaluate("groupSubmitted")), "Group assignment did not require explicit confirmation");
            await browser.evaluate(`groupActionForm.elements.confirm_assignment.focus()`);
            await browser.space();
          }
          await browser.evaluate(`groupActionForm.querySelector('button').focus()`);
          await browser.enter();
          const fields = await browser.evaluate("groupSubmittedFields");
          browser.check(fields.csrf === "owned-csrf" && fields.group_id === groupID && fields.group_revision === "3" && fields.devices === "30000000-0000-4000-8000-000000000001", "Keyboard submission changed the group or target evidence");
        }
      }
      if (width === 390) await browser.capture("windows-group-" + state + "-390");
      record({ name: "Windows group assignment " + state, width, passed: true });
    }
  }
}
