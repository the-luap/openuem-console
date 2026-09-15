export default async function run(browser,record) {
 const {visit,evaluate,check,enter,capture}=browser;
 for (const state of ["browser","en","de","es","ca","fr","no","pt","unavailable","long"])
  for (const width of [390,768,1440]) {
   await visit("account-language-"+state,width);
   const code=["browser","unavailable","long"].includes(state)?"en":state;
   check(await evaluate("document.documentElement.lang")==code,"Account document language does not follow the selected catalog");
   check(await evaluate(`document.querySelector('#account-language-title').textContent==='Display language' && !document.body.textContent.includes('!(MISSING:')`),"Missing English fallback in account language controls");
   if (state==="unavailable") {
    check(await evaluate(`!document.querySelector('#account-language') && document.querySelector('[aria-labelledby="account-language-title"] [role="status"]').textContent.includes('unavailable')`),"Unavailable preference offers a save");
   } else {
    const data=await evaluate(`(()=>{const select=document.querySelector('#account-language');return {value:select.value,options:[...select.options].map(o=>o.value),label:select.labels[0].textContent,help:select.getAttribute('aria-describedby')};})()`);
    check(data.value===(state==="browser"?"":code) && data.options.join(",")===",en,ca,fr,de,no,pt,es" && data.label==="Language" && data.help==="account-language-help","Account choice, labels or supported catalogs changed");
    await evaluate(`window.posts=[];window.f=document.querySelector('form[action="/myaccount/language"]');f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();posts.push({method:f.method,path:new URL(f.action).pathname,fields:[...new FormData(f)]});},true);f.elements.locale.value='fr';f.querySelector('button').focus();`);
    await enter();
    const posts=await evaluate("posts");
    check(posts.length===1 && posts[0].method==="post" && posts[0].path==="/myaccount/language" && JSON.stringify(posts[0].fields)===JSON.stringify([["csrf","owned-language-csrf"],["locale","fr"]]),"Keyboard save lost its CSRF token or targeted another account");
   }
   check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Account profile overflows viewport");
   if(width===390 && ["en","de","unavailable","long"].includes(state)) {
    await evaluate("scrollTo(0,0)");await capture("account-language-"+state+"-390");
   }
   record({name:"Account language "+state,width,passed:true});
  }
}
