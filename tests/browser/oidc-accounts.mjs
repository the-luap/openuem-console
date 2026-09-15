export default async function run(browser,record) {
 const {visit,evaluate,check,enter,capture}=browser;
 for (const state of ["unlinked","active","disabled","ineligible","long","provider_disabled"])
  for (const width of [390,768,1440]) {
   await visit("oidc-accounts-"+state,width);
   check(await evaluate(`document.querySelector('h1').textContent==='OpenID account identity' && !document.querySelector('main img,main iframe') && !window.__ownedOIDC`),"Identity claims injected markup or lost page title");
   const canLink=["unlinked","disabled"].includes(state);
   check(await evaluate(`Boolean(document.querySelector('[data-oidc-link]'))`)==canLink,"Identity link eligibility changed");
   if (!["ineligible","provider_disabled"].includes(state)) {
    await evaluate(`window.posts=[];window.f=document.querySelector('main form[method="post"]');f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();posts.push({method:f.method,path:f.getAttribute('action'),fields:Object.fromEntries(new FormData(f))});},true);if(f.elements.subject.type!=='hidden')f.elements.subject.value='exact-subject';f.querySelector('button').focus();`);
    await enter();
    check(await evaluate("posts.length===0"),"Identity change did not require explicit confirmation");
    await evaluate(`f.elements.confirmed.checked=true;f.querySelector('button').focus()`);
    await enter();
    const posts=await evaluate("posts");
    const uid=state==="long"?"account".repeat(35):"legacy-account";
    const issuer="https://identity.example.test"+(state==="long"?"/"+"issuer".repeat(300):"");
    check(posts.length===1 && posts[0].method==="post" && posts[0].path==="/admin/oidc-accounts" && posts[0].fields.csrf==="owned-oidc-csrf" && posts[0].fields.user_id===uid && posts[0].fields.revision==="3" && posts[0].fields.issuer===issuer && posts[0].fields.client_id==="owned-client" && posts[0].fields.confirmed==="yes","Identity form lost account, provider, CSRF or revision binding");
    check(posts[0].fields.action===(canLink?"link":"disable"),"Identity confirmation changed action");
   } else check(await evaluate(`document.querySelectorAll('main form[method="post"]').length===0`),"Unavailable identity account offers a mutation");
   check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Identity page overflows viewport");
   if(width===390 && ["unlinked","active","long"].includes(state)) {await evaluate("scrollTo(0,0)");await capture("oidc-accounts-"+state+"-390");}
   record({name:"OpenID account "+state,width,passed:true});
  }
}
