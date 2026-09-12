export default async function run(browser,record) {
 const {visit,evaluate,check}=browser;
 const months={en:"Jan",de:"Jan",ca:"gen",es:"ene",fr:"janv",no:"jan",pt:"jan"};
 for(const locale of Object.keys(months))
  for(const width of [390,768,1440]) {
   await visit("timestamps-"+locale,width);
   const first=await evaluate(`document.querySelector('#time-0 time').textContent`);
   check(first.includes("2026") && first.toLowerCase().includes(months[locale].toLowerCase()) && first.includes("03:04") && first.endsWith(" UTC"),"Timestamp lost its locale, UTC hour or explicit zone");
   check(await evaluate(`document.querySelector('#time-0 time').dateTime==='2026-01-02T03:04:56Z' && document.querySelector('#time-0 time').title==='2026-01-02T03:04:56Z'`),"Timestamp changed the exact machine-readable instant");
   check(await evaluate(`document.querySelector('#time-4 time').textContent.includes('03:04:56') && document.querySelector('#time-4 time').textContent.endsWith(' UTC')`),"Audit precision was reduced to minutes");
   const dst=await evaluate(`[...document.querySelectorAll('#time-1 time,#time-2 time')].map(t=>t.textContent)`);
   check(dst[0].includes(locale==="en"?"12:30":"00:30") && dst[1].includes("01:30") && dst.every(text=>text.endsWith(" UTC")),"Browser daylight-saving rules changed UTC report times");
   check(await evaluate(`document.querySelector('#time-3').textContent==='Never reported' && !document.querySelector('#time-3 time') && document.querySelector('#device-deadline span').textContent==='2026-03-29T02:30:00'`),"Missing report or device-local deadline was converted");
   // Exercise a real DOM insertion, as used by partial-page navigation.
   await evaluate(`window.dynamic=document.createElement('time');dynamic.setAttribute('data-uem-timestamp','');dynamic.lang='de';dynamic.dateTime='2026-12-31T23:59:00Z';dynamic.textContent='2026-12-31 23:59 UTC';document.querySelector('main').append(dynamic);`);
   await evaluate(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
   check(await evaluate(`dynamic.textContent.includes('Dez') && dynamic.textContent.includes('23:59') && dynamic.textContent.endsWith(' UTC')`),"Inserted report did not use its own server-selected locale");
   // Missing Intl support and invalid values retain safe server text.
   await evaluate(`window.originalFormatter=Intl.DateTimeFormat;Intl.DateTimeFormat=class {constructor(){throw new RangeError('owned unavailable formatter')}};window.fallback=document.createElement('time');fallback.setAttribute('data-uem-timestamp','');fallback.lang='it';fallback.dateTime='2026-12-31T23:59:00Z';fallback.textContent='2026-12-31 23:59 UTC';document.querySelector('main').append(fallback);window.invalid=fallback.cloneNode();invalid.lang='en';invalid.dateTime='not a timestamp';invalid.textContent='<img src=x>';document.querySelector('main').append(invalid);`);
   await evaluate(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
   check(await evaluate(`fallback.textContent==='2026-12-31 23:59 UTC' && invalid.textContent==='<img src=x>' && !invalid.querySelector('img')`),"Timestamp fallback was lost or interpreted as markup");
   await evaluate(`Intl.DateTimeFormat=originalFormatter`);
   check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Timestamp fixture overflows");
   record({name:"Localized UTC timestamps "+locale,width,passed:true});
  }
}
