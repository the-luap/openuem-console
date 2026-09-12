export default async function run(browser,record) {
 for(const state of ['choose','empty','preview','remove','excluded','assignment','history','reader','receipt-site-operator','long'])for(const width of [390,768,1440]) {
  await browser.visit('apple-profile-group-organization-'+state,width);
  const v=await browser.evaluate(`(()=>{const m=document.querySelector('[data-profile-groups]');const f=m.querySelector('form');return {width:document.documentElement.scrollWidth,viewport:innerWidth,text:m.textContent,scripts:m.querySelectorAll('script').length,form:f?{action:f.getAttribute('action'),fields:Object.fromEntries(new FormData(f)),required:f.elements.confirmed.required}:null,links:[...m.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))}})()`);
  browser.check(v.width<=v.viewport+1&&v.scripts===0,'Organization profile group overflows or executes source markup');
  const editable=['preview','remove','long'].includes(state);
  browser.check(!!v.form===editable,'Read-only organization group exposes assignment');
  const profile='/tenant/1/site/1/ios/configurations/20000000-0000-0000-0000-000000000001';
  if(state==='choose'||state==='empty') {
   browser.check(v.text.includes('only within the selected target site')&&v.links.some(a=>a.text==='Site groups'&&a.href.startsWith(profile+'/groups?')&&!a.href.includes('source=organization'))&&v.links.some(a=>a.text==='Manage dynamic groups'&&a.href==='/tenant/1/device-groups'),'Chooser loses source organization or target site');
   if(state==='choose')browser.check(v.links.filter(a=>a.text==='Review this group').length===1&&v.links.some(a=>a.text==='Review this group'&&a.href.includes('source=organization')&&a.href.includes('group_revision=3')),'Organization choice lost source intent or archived exclusion');
   if(state==='empty')browser.check(v.text.includes('No dynamic groups in this organization'),'Empty source is mislabeled as target site');
  } else if(state==='history') {
   browser.check(v.text.includes('Source: organization group · Target site: 1')&&v.links.some(a=>a.text==='Older assignments'&&a.href.startsWith(profile+'/group-assignments?before=')),'History loses source kind or target-site pagination');
  } else {
   browser.check(v.text.includes("Only the selected target site's members are included")&&v.text.includes('Target site: 1 · Organization: 1'),'Preview or receipt hides the source/target intersection');
   const groupLinks=v.links.filter(a=>a.text==='Open the current organization group and its history');
   browser.check(groupLinks.length===(state==='receipt-site-operator'?0:1)&&groupLinks.every(a=>a.href==='/tenant/1/device-groups/30000000-0000-0000-0000-000000000001'),'Historical source links use the wrong scope or bypass organization visibility');
  }
  if(editable) {
   const f=v.form;
   browser.check(f.action===profile+'/group-assignments'&&f.required&&f.fields.group_source==='organization'&&f.fields.expected_revision==='2'&&f.fields.group_revision==='3'&&f.fields.devices==='10000000-0000-0000-0000-000000000001'&&f.fields.csrf==='owned-csrf'&&f.fields.desired===(state==='remove'?'removed':'installed'),'Reviewed organization source, action or target was lost');
   await browser.evaluate(`(()=>{window.organizationGroupSubmissions=[];const f=document.querySelector('[data-profile-group-confirm]');f.addEventListener('submit',e=>{e.preventDefault();window.organizationGroupSubmissions.push(Object.fromEntries(new FormData(f,e.submitter)))});f.querySelector('button').focus()})()`);await browser.enter();
   browser.check(await browser.evaluate('window.organizationGroupSubmissions.length')===0,'Unconfirmed organization profile assignment submitted');
   await browser.evaluate("document.querySelector('[data-profile-group-confirm]').elements.confirmed.focus()");await browser.space();await browser.tab();await browser.enter();
   const submitted=await browser.evaluate('window.organizationGroupSubmissions');browser.check(submitted.length===1&&submitted[0].confirmed==='yes'&&Object.entries(f.fields).every(([k,value])=>submitted[0][k]===value),'Keyboard assignment changed reviewed intersection');
  }
  if(width===390){await browser.evaluate("document.querySelector('[data-profile-groups]').scrollIntoView({block:'start'})");await browser.capture('apple-profile-group-organization-'+state+'-390');}
  record({name:'Apple organization profile group '+state,width,passed:true});
 }
}
