// Approvals are exercised against inert rendered fixtures. Submit handlers stop
// navigation before the read-only fixture server can receive a mutation.
export default async function run(browser, record) {
  const {visit,evaluate,check,enter,capture}=browser;
  const states=["approve-winget","approve-msi","approve-exe","detail-winget","detail-msi","detail-exe","reader","withdrawn","catalog"];
  for (const state of states) for (const width of [390,768,1440]) {
    await visit("windows-software-"+state,width);
    check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe').length===0`),"Catalog data injected markup");
    if (state.startsWith("approve-")) {
      const kind="windows-"+state.slice(8);
      const formValues={name:'Owned package',identifier:'Vendor.Product',version:'1.2.3',minimum_os:'10.0.26100',source_url:`https://example.test/owned.${state.endsWith("msi")?"msi":"exe"}`,sha256:'a'.repeat(64),install_arguments:'/quiet\nexact argument',msi_properties:'LICENSEKEY=owned-fixture',uninstall_url:'https://example.test/remove.exe',uninstall_sha256:'b'.repeat(64),uninstall_arguments:'/quiet\nremove',product_code:'{AABBCCDD-0000-4000-8000-000000000001}',detection_version:'1.2.3'};
      await evaluate(`window.f=document.querySelector('main form[method="post"]');window.submissions=[];
        f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({path:new URL(f.action).pathname,fields:Object.fromEntries(new FormData(f))})},true);
        const values=${JSON.stringify(formValues)};
        for(const [name,value] of Object.entries(values)) if(f.elements[name]) f.elements[name].value=value;
        f.requestSubmit();
      `);
      check(await evaluate("submissions.length===0 && !f.elements.confirmed.checked"),"Approval did not require explicit confirmation");
      await evaluate("f.elements.confirmed.checked=true;f.querySelector('button[type=submit]').focus()");
      await enter();
      const submissions=await evaluate("submissions");
      check(submissions.length===1 && submissions[0].path==="/tenant/1/software/catalog/windows","Keyboard approval changed route or scope");
      const values=submissions[0].fields;
      check(values.kind===kind && values.confirmed==="yes" && values.request_id==="90000000-0000-4000-8000-000000000031" && values.csrf==="test-csrf-token","Approval lost kind, identity, CSRF or confirmation");
      if(kind==="windows-exe") check(values.install_arguments==="/quiet\nexact argument" && values.uninstall_arguments==="/quiet\nremove","EXE arguments were interpreted as command text");
      if(kind==="windows-msi") check(values.msi_properties==="LICENSEKEY=owned-fixture" && values.reboot_codes==="3010","MSI intent changed");
    } else if(state==="catalog") {
      check(await evaluate(`!document.querySelector('main form[method="post"]')`),"Catalog reader received approval controls");
      const link=await evaluate(`(() => {const a=[...document.querySelectorAll('main a')].find(a=>a.textContent==='Older revisions');return {path:new URL(a.href).pathname,q:new URL(a.href).searchParams.get('q'),platform:new URL(a.href).searchParams.get('platform')}})()`);
      check(link.path==="/tenant/1/software/catalog" && link.q==="%_&" && link.platform==="windows","Catalog cursor lost filters or scope");
      await evaluate(`window.f=document.querySelector('main form[method="get"]');window.submissions=[];f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push(Object.fromEntries(new FormData(f)))},true);f.elements.q.value='%_& new';f.elements.q.focus()`);
      await enter();
      check(await evaluate("submissions.length===1 && submissions[0].q==='%_& new' && submissions[0].platform==='windows' && !('before' in submissions[0])"),"Search retained stale pagination");
    } else {
      check(await evaluate(`document.querySelector('main').textContent.includes('Windows approval recorded') && !document.querySelector('main').textContent.includes('Install on a Mac') && !document.querySelector('main').textContent.includes('Request installation')`),"Windows approval exposed an unsupported installation action");
      if(["reader","withdrawn"].includes(state)) check(await evaluate(`!document.querySelector('main form[method="post"]')`),"Read-only or withdrawn approval exposed mutations");
      else check(await evaluate(`document.querySelector('main form').elements.confirmed.required`),"Withdrawal lost confirmation");
    }
    check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Windows catalog page overflow");
    if(width===390 && ["approve-exe","detail-msi","catalog"].includes(state)) {
      await evaluate("window.scrollTo(0,0)");
      await capture("windows-software-"+state+"-390");
    }
    record({name:"Windows software catalog "+state,width,passed:true});
  }
}
