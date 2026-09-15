import { checkCurrentLink } from "./inventory-navigation.mjs";

export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const width of [390, 768, 1440]) {
    await visit("notes-conflict", width);
    await checkCurrentLink(browser, "Computer inventory", "Device notes");
    check(await evaluate(`!window.notesOwned && !window.draftOwned && document.querySelectorAll('main img, main iframe, main script').length === 0`), "Private notes loaded active or remote content");
    check(await evaluate(`document.querySelector('#device-notes').value === 'My draft </textarea><script>window.draftOwned=true</script>'`), "Conflict changed the submitted draft");
    check(await evaluate(`document.querySelector('[role="alert"]').textContent.includes('Your draft is preserved')`), "Conflict review instructions missing");
    check(await evaluate(`Number(getComputedStyle(document.querySelector('.markdown-body strong')).fontWeight) >= 600`), "Saved Markdown formatting missing");
    await evaluate(`
      window.notesForm = document.querySelector('main form');
      window.notesSubmissions = [];
      notesForm.addEventListener('submit', event => {
        event.preventDefault(); event.stopImmediatePropagation();
        notesSubmissions.push({method: notesForm.method, path: new URL(notesForm.action).pathname, fields: Object.fromEntries(new FormData(notesForm))});
      }, true);
      notesForm.elements.markdown.value = 'Merged current notes and draft';
      notesForm.querySelector('button[type="submit"]').focus();
    `);
    await enter();
    const submissions = await evaluate("notesSubmissions");
    check(submissions.length === 1 && submissions[0].method === "post" && submissions[0].path === "/tenant/1/site/1/computers/notes-device/notes", "Notes save lost its method or scope");
    const fields = submissions[0].fields;
    check(Object.keys(fields).sort().join(",") === "csrf,markdown,revision" && fields.markdown === "Merged current notes and draft" && fields.revision === "f531367c-00bc-4f1a-a8ed-6162d9923716", "Notes save lost the draft, current revision or CSRF field");
    check(await evaluate(`notesForm.getAttribute('hx-boost') === 'false' && document.documentElement.scrollWidth <= innerWidth + 1`), "Notes conflict navigation or viewport changed");
    if (width === 390) await capture("desktop-notes-conflict-390");
    record({name: "Desktop notes conflict and Markdown privacy", width, passed: true});
  }
}
