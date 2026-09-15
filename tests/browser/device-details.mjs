import { checkCurrentLink } from "./inventory-navigation.mjs";

export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const state of ["edit", "conflict", "empty", "long"])
    for (const width of [390, 768, 1440]) {
      await visit("device-details-" + state, width);
      await checkCurrentLink(browser, "Computer inventory", "Device details");
      check(await evaluate(`!window.detailsOwned && !window.draftOwned && document.querySelectorAll('main script,main iframe,main img').length===0`), "Device labels introduced active or remote content");
      check(await evaluate(`document.querySelector('main').textContent.includes('does not rename the operating system')`), "Display name incorrectly implies a native rename");
      const conflict = state === "conflict" || state === "long";
      if (conflict) {
        check(await evaluate(String.raw`document.querySelector('#device-nickname').value==='Draft <script>window.draftOwned=true</script>' && document.querySelector('#device-description').value==='Draft </textarea><script>window.draftOwned=true</script>\nPreserved second line' && document.querySelector('#device-type').value==='Server'`), "Conflict lost a submitted field");
        check(await evaluate(`document.querySelector('[role="alert"]').textContent.includes('Your draft is preserved') && document.querySelector('main').textContent.includes('Currently saved values')`), "Conflict does not explain current values");
      }
      if (state === "empty") check(await evaluate(`document.querySelector('h1').textContent==='finance-host' && document.querySelector('#device-nickname').value==='' && document.querySelector('#device-description').value===''`), "Cleared labels lost hostname fallback");
      check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"), "Device details page overflow");
      if ((width===390 && conflict) || (width===1440 && state==="conflict")) {
        await evaluate("window.scrollTo(0,0)");
        await capture("device-details-"+state+"-"+width);
      }
      await evaluate(`window.detailsForm=document.querySelector('main form');window.submissions=[];detailsForm.addEventListener('submit',event=>{event.preventDefault();event.stopImmediatePropagation();submissions.push({method:detailsForm.method,path:new URL(detailsForm.action).pathname,fields:Object.fromEntries(new FormData(detailsForm))});},true);detailsForm.elements.nickname.value='';detailsForm.elements.description.value='';detailsForm.elements.endpoint_type.value='Other';detailsForm.querySelector('button[type="submit"]').focus();`);
      await enter();
      const sent = await evaluate("submissions");
      check(sent.length===1 && sent[0].method==="post" && sent[0].path==="/tenant/1/site/1/computers/details-device/details", "Saving details lost its native scope");
      const fields=sent[0].fields;
      check(Object.keys(fields).sort().join(",")==="csrf,description,endpoint_type,nickname,revision" && fields.nickname==="" && fields.description==="" && fields.endpoint_type==="Other" && fields.revision==="350542db-5a9f-4a88-97cb-4b70d5f164d1", "Clearing details lost exact fields, revision or CSRF");
      record({name:"Device details "+state,width,passed:true});
    }
}
