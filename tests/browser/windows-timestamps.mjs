export default async function run(browser,record) {
 const {visit,evaluate,check}=browser;
 for(const locale of ["en","de","ca","es","fr","no","pt"])
  for(const width of [390,768,1440]) {
   await visit("windows-timestamps-"+locale,width);
   const times=await evaluate(`[...document.querySelectorAll('time')].map(node=>({text:node.textContent,iso:node.dateTime,title:node.title}))`);
   const decimal=locale==="en"?".":",";
   const hour=locale==="en"?"11":"23";
   check(times.length===4 && times[0].text.includes(hour+":59:59") && times[0].text.endsWith(" UTC"),"Whole-second Windows time lost UTC or precision");
   check(times[1].text.includes(hour+":59:59"+decimal+"123456789") && times[1].text.endsWith(" UTC"),"Windows command time lost submillisecond digits");
   check(times[2].text.includes(hour+":59:59"+decimal+"000000001") && times[2].text.endsWith(" UTC"),"Windows command time lost leading fractional zeros");
   check(times[1].iso==="2026-12-31T23:59:59.123456789Z" && times[1].title===times[1].iso && times[2].iso==="2026-12-31T23:59:59.000000001Z", "Localization altered exact command evidence");
   check(times[3].text.includes(hour+":59") && !times[3].text.includes(":59:59") && times[3].text.endsWith(" UTC"),"Ordinary enrollment time gained unrequested precision");
   check(await evaluate(`document.querySelector('#missing').textContent==='Not received' && !document.querySelector('#missing time')`),"Missing Windows result became a timestamp");
   check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Windows timestamp fixture overflows");
   record({name:"Windows precise timestamps "+locale,width,passed:true});
  }
}
