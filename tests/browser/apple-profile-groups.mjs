export default async function run(browser, record) {
  for (const state of ["choose", "empty", "preview", "remove", "excluded", "assignment", "history", "empty-history", "long", "catalog"]) {
    for (const width of [390, 768, 1440]) {
      await browser.visit("apple-profile-group-" + state, width);
      const view = await browser.evaluate(`(() => {
        const main = document.querySelector('[data-profile-groups],#apple-profiles');
        window.groupForm = main.querySelector('[data-profile-group-confirm]');
        return {text:main.textContent, links:[...main.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')})),
          form:!!groupForm, required:groupForm?.elements.confirmed.required,
          inputs:groupForm ? [...groupForm.querySelectorAll('input')].map(e=>({name:e.name,type:e.type})):[],
          width:document.documentElement.scrollWidth,viewport:innerWidth};
      })()`);
      browser.check(view.width <= view.viewport + 1, "Apple group page overflows the viewport");
      if (["preview", "remove", "long"].includes(state)) {
        browser.check(view.form && view.required, "Group confirmation is missing its required confirmation");
        browser.check(view.inputs.every(e => e.name === "confirmed" ? e.type === "checkbox" : e.type === "hidden"), "Reviewed group or devices can be edited in the confirmation form");
        await browser.evaluate(`(() => {
          groupForm.addEventListener('submit', event => {event.preventDefault();window.groupFields=Object.fromEntries(new FormData(groupForm,event.submitter));});
          groupForm.querySelector('button').focus();
        })()`);
        await browser.enter();
        browser.check(await browser.evaluate("!window.groupFields"), "An unchecked confirmation submitted");
        await browser.evaluate("groupForm.elements.confirmed.checked=true;groupForm.querySelector('button').focus()");
        await browser.enter();
        const fields = await browser.evaluate("window.groupFields");
        browser.check(fields.expected_revision === "2" && fields.group_revision === "3" && fields.group_id === "30000000-0000-0000-0000-000000000001" && fields.request_key === "50000000-0000-0000-0000-000000000001" && fields.devices === "10000000-0000-0000-0000-000000000001" && fields.csrf === "owned-csrf" && fields.confirmed === "yes" && fields.desired === (state === "remove" ? "removed" : "installed"), "Keyboard confirmation changed the reviewed request");
        browser.check(await browser.evaluate("groupForm.getAttribute('action')==='/tenant/1/site/1/ios/configurations/20000000-0000-0000-0000-000000000001/group-assignments'"), "Confirmation lost its site or profile scope");
      } else {
        browser.check(!view.form, "A read-only group state offered confirmation");
      }
      if (state === "catalog") {
        const links = view.links.filter(a=>a.text.includes("dynamic group"));
        browser.check(links.length === 2, "Site catalog lost apply/removal group entry points");
        for (const link of links) {
          const url = new URL(link.href, "http://fixture");
          browser.check(url.pathname === "/tenant/1/site/1/ios/configurations/20000000-0000-0000-0000-000000000001/groups" && url.searchParams.get('revision') === '2' && url.searchParams.get('desired') === (link.text.startsWith('Apply') ? 'installed' : 'removed'), "Catalog group link lost current revision, scope or action");
        }
        browser.check(view.links.some(a=>a.text === "Group assignment history" && a.href.endsWith("/group-assignments")), "Catalog lost group history");
      }
      if (state === "choose") {
        const reviews = view.links.filter(a=>a.text === "Review this group");
        browser.check(reviews.length === 1 && view.text.includes("Archived; unavailable"), "Archived group offered new work");
        const link = new URL(reviews[0].href, "http://fixture");
        browser.check(link.pathname.endsWith('/groups/30000000-0000-0000-0000-000000000001/preview') && link.searchParams.get('revision') === '2' && link.searchParams.get('group_revision') === '3' && link.searchParams.get('desired') === 'installed', "Chooser lost the reviewed revisions or action");
      }
      if (state === "excluded") browser.check(view.text.includes("No members can receive") && view.text.includes("Owned Windows"), "All-excluded preview lost its explanation");
      if (state === "empty") browser.check(view.text.includes("No dynamic groups"), "Empty chooser lost its explanation");
      if (state === "empty-history") browser.check(view.text.includes("No confirmed group assignments") && !view.links.some(a=>a.text === "Older assignments"), "Empty history offered another page");
      if (state === "assignment") browser.check(view.text.includes("Original group assignment") && view.text.includes("Owned <Apple group>") && view.text.includes("60000000-0000-0000-0000-000000000001") && view.links.some(a=>a.href === "/tenant/1/site/1/ios/10000000-0000-0000-0000-000000000001"), "Original receipt lost source, command or current-device navigation");
      if (state === "history") browser.check(view.links.some(a=>a.text === "Older assignments" && a.href.endsWith("?before=40000000-0000-0000-0000-000000000001")), "History pagination lost its cursor");
      if (width === 390) await browser.capture("apple-profile-group-" + state + "-390");
      record({name:"Apple profile group " + state, width, passed:true});
    }
  }
}
