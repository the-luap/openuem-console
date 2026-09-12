export default async function run(browser, record) {
  for (const state of ["profiles", "device-stale-assignment", "device-unavailable-source"]) {
    for (const width of [390, 768, 1440]) {
      await browser.visit(state, width);
      const result = await browser.evaluate(`(() => {
        window.assignmentForm = document.querySelector('form[action$="/20000000-0000-0000-0000-000000000001/assign"]');
        return {groupLinks:!!document.querySelector('[data-profile-group-actions]'), form:!!assignmentForm, revision:assignmentForm?.elements.expected_revision?.value,
          fields:assignmentForm?.querySelectorAll('[name="expected_revision"]').length,
          current:document.body.textContent.includes('Current profile revision: 2'),
          width:document.documentElement.scrollWidth,viewport:innerWidth};
      })()`);
      browser.check(result.width <= result.viewport + 1, "Apple profile assignment overflows the viewport");
      if (state === "profiles") browser.check(!result.groupLinks, "Organization catalog offered site-only group actions");
      if (state === "device-unavailable-source") {
        browser.check(!result.form, "Missing catalog source still offers an assignment");
      } else {
        browser.check(result.form && result.revision === "2" && result.fields === 1, "Assignment lost the reviewed catalog revision");
        if (state === "device-stale-assignment") browser.check(result.current, "Current source revision is missing beside older assigned evidence");
        await browser.evaluate(`(() => {
          const selection=assignmentForm.elements.device_id;
          if(selection.tagName==='SELECT') selection.options[0].selected=true;
          assignmentForm.addEventListener('submit',event=>{
            event.preventDefault();window.assignmentFields=Object.fromEntries(new FormData(assignmentForm,event.submitter));
          });
        })()`);
        for (const desired of ["installed", "removed"]) {
          await browser.evaluate(`assignmentForm.querySelector('button[name="desired"][value="${desired}"]').focus()`);
          await browser.enter();
          const fields = await browser.evaluate("window.assignmentFields");
          browser.check(fields.desired === desired && fields.expected_revision === "2" && fields.csrf === "test-csrf-token" && fields.device_id === "10000000-0000-0000-0000-000000000001", "Keyboard assignment changed its source, device, action or CSRF token");
        }
      }
      if (width === 390) await browser.capture("apple-profile-assignment-" + state + "-390");
      record({name: "Apple profile assignment " + state, width, passed: true});
    }
  }
}
