export default async function run(browser,record) {
 for(const state of ['list','empty','detail','archived','viewer','long']) {
  for(const width of [390,768,1440]) {
   await browser.visit('apple-update-plan-'+state,width);
   const view=await browser.evaluate(`(()=>{
    const main=document.querySelector('[data-update-plans]');window.planForm=main.querySelector('form[aria-label="Save Apple update plan"]');
    return {width:document.documentElement.scrollWidth,viewport:innerWidth,form:!!planForm,text:main.textContent,revision:planForm?.elements.expected_revision.value,archived:planForm?.elements.archived.checked,links:[...main.querySelectorAll('a')].map(a=>a.getAttribute('href'))};
   })()`);
   browser.check(view.width<=view.viewport+1,'Apple update plan overflows viewport');
   if(state==='viewer')browser.check(!view.form,'Viewer can edit an update plan');
   else {
    const creating=['list','empty'].includes(state);
    browser.check(view.form && view.revision===(creating?'0':'3') && view.archived===(state==='archived'),'Plan form lost current revision or archive state');
    await browser.evaluate(`(()=>{
     if(${creating}){planForm.elements.name.value='Owned browser pilot';planForm.elements.target_version.value='18.7.1';planForm.elements.target_build.value='22H100';planForm.elements.deadline.value='2026-10-01T18:00:00';}
     planForm.addEventListener('submit',event=>{event.preventDefault();window.planFields=Object.fromEntries(new FormData(planForm,event.submitter));});
     planForm.querySelector('button').focus();
    })()`);
    await browser.enter();
    const fields=await browser.evaluate('window.planFields');
    browser.check(fields && fields.csrf==='owned-csrf' && fields.expected_revision===(creating?'0':'3') && fields.target_version==='18.7.1' && fields.target_build==='22H100' && fields.platform==='ios' && fields.deadline.startsWith('2026-10-01T18:00') && (fields.archived==='yes')===(state==='archived'),'Keyboard plan save lost reviewed fields');
    browser.check(await browser.evaluate(`planForm.getAttribute('action')==='/tenant/1/site/1/ios/update-plans${creating?'':'/70000000-0000-0000-0000-000000000001'}'`),'Plan save changed scope or source identity');
   }
   if(['detail','archived','viewer','long'].includes(state)) browser.check(view.text.includes('Previous <pilot>') && view.text.includes('22H90') && view.links.some(a=>a.endsWith('?before=2')),'Retained plan history or revision paging missing');
   if(state==='empty')browser.check(view.text.includes('No Apple update plans'),'Empty plan catalog lost explanation');
   if(width===390)await browser.capture('apple-update-plan-'+state+'-390');
   record({name:'Apple update plan '+state,width,passed:true});
  }
 }
}
