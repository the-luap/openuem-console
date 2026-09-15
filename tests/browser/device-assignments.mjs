import { checkCurrentLink } from "./inventory-navigation.mjs";

export default async function run(browser, record) {
  const { visit, evaluate, check, enter, space, capture } = browser;
  for (const state of ["choices", "choices-long", "individual", "review-site", "review-organization", "completed", "expired", "conflict"])
    for (const width of [390, 768, 1440]) {
      await visit("device-assignment-" + state, width);
      check(await evaluate(`!window.assignmentOwned && document.querySelectorAll('main script,main iframe,main img').length===0`), "Assignment names injected active markup");
      if (state.startsWith("choices") || state === "individual") await checkCurrentLink(browser, "Computer inventory", "Assignment");
      if (state.startsWith("choices")) {
        check(await evaluate(`Array.from(document.querySelectorAll('input[name="destination_site"]')).every(e=>e.getBoundingClientRect().width>=14)`), "Destination controls collapsed beside long names");
        check(await evaluate(`document.querySelector('#assignment-search').value === '%_&'`), "Destination search changed literal input");
        check(await evaluate(`(() => {const link=document.querySelector('nav[aria-label="Destination pages"] a');const u=new URL(link.href);return u.pathname==='/tenant/1/site/1/computers/assignment-device/assignment' && u.searchParams.get('q')==='%_&' && u.searchParams.get('after')==='3';})()`), "Destination continuation lost scope or search");
        await evaluate(`window.form=document.querySelector('main form[method="post"]');window.sent=[];form.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();sent.push({method:form.method,path:new URL(form.action).pathname,fields:Object.fromEntries(new FormData(form))});},true);form.querySelector('button').focus();`);
        await enter();
        check(await evaluate("sent.length===0"), "Missing destination submitted a review");
        await evaluate(`form.querySelector('input[value="3"]').focus()`);
        await space();
        await evaluate(`form.querySelector('button').focus()`);
        await enter();
        const sent=await evaluate("sent");
        check(sent.length===1 && sent[0].method==="post" && sent[0].path==="/tenant/1/site/1/computers/assignment-device/assignment" && sent[0].fields.destination_site==="3" && Object.keys(sent[0].fields).sort().join(",")==="csrf,destination_site", "Destination review lost its exact scope, selection or CSRF field");
      } else if (state.startsWith("review")) {
        const text=await evaluate("document.querySelector('main').textContent");
        check(text.includes("Existing notes and inventory reports move with the device"), "Retained data transfer was hidden");
        check(text.includes(state==="review-site"?"keeps the device's tags":"permanently removes all tag assignments"), "Review misrepresented metadata and tag removal");
        await evaluate(`window.form=document.querySelector('main form');window.sent=[];form.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();sent.push({method:form.method,path:new URL(form.action).pathname,fields:Object.fromEntries(new FormData(form))});},true);form.querySelector('button').focus();`);
        await enter();
        check(await evaluate("sent.length===0"), "Unconfirmed move was submitted");
        await evaluate(`form.querySelector('input[name="confirm"]').focus()`);
        await space();
        await evaluate(`form.querySelector('button').focus()`);
        await enter();
        const sent=await evaluate("sent");
        check(sent.length===1 && sent[0].method==="post" && sent[0].path==="/tenant/1/site/1/computers/assignment-device/assignment/a938f203-9961-4f40-8896-2e69d3f1225e" && sent[0].fields.confirm==="yes" && Object.keys(sent[0].fields).sort().join(",")==="confirm,csrf", "Confirmation replaced the reviewed target or lost its CSRF field");
      } else {
        check(await evaluate(`document.querySelectorAll('main form[method="post"]').length===0`), "Unavailable or completed assignment retained a mutation form");
        if(state==="individual") check(await evaluate(`document.querySelector('main').textContent.includes('individual enrollment identity')`), "Certificate scope boundary missing");
        if(state==="completed") check(await evaluate(`document.querySelector('main').textContent.includes('Device moved') && [...document.querySelectorAll('main a')].some(a=>new URL(a.href).pathname==='/tenant/2/site/3/computers/assignment-device/inventory')`), "Completed receipt lost its destination");
        if(state==="expired"||state==="conflict") check(await evaluate(`document.querySelector('main').textContent.includes('Nothing was moved by this request')`), "Failed review claimed a move");
      }
      check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"), "Assignment page overflow");
      if((width===390 && ["choices-long","review-organization","completed"].includes(state)) || (width===1440 && state==="review-organization")) {
        await evaluate("window.scrollTo(0,0)");
        await capture("device-assignment-"+state+"-"+width);
      }
      record({name:"Device assignment "+state,width,passed:true});
    }
}
