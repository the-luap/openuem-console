export default async function run(browser,record) {
 return runPromotionCases(browser,record,['plans','empty-plans','groups','empty-groups','ready','overlap','unknown','stale','error','exception','post-exception','different-policy','unavailable','incompatible','pilot-only','viewer','receipt','history','empty-history','long']);
}

export async function runPromotionCases(browser,record,states,organization=false) {
 for(const state of states)for(const width of [390,768,1440]) {
  const fixture=(organization?'organization-':'')+state;
  await browser.visit('apple-update-promotion-'+fixture,width);
  const v=await browser.evaluate(`(()=>{const m=document.querySelector('[data-update-promotion-page]');return {width:document.documentElement.scrollWidth,viewport:innerWidth,page:m.dataset.updatePromotionPage,text:m.textContent,scripts:m.querySelectorAll('script').length,forms:[...m.querySelectorAll('form')].map(f=>({action:f.getAttribute('action'),fields:Object.fromEntries(new FormData(f)),required:f.elements.confirmed.required})),links:[...m.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')})),plans:[...m.querySelectorAll('[data-promotion-plan]')].map(p=>({id:p.dataset.promotionPlan,links:p.querySelectorAll('a').length})),targets:m.querySelectorAll('[data-promotion-target]').length,proofs:m.querySelectorAll('[data-promotion-proof]').length}})()`);
  browser.check(v.width<=v.viewport+1&&v.scripts===0,'Promotion page overflows or executes source markup');
  const editable=['ready','overlap','long'].includes(state);
  browser.check(v.forms.length===(editable?1:0),'Blocked, historical or viewer page exposes promotion');
  const base='/tenant/1/site/1/ios/update-plans/30000000-0000-4000-8000-000000000001/group-assignments/40000000-0000-4000-8000-000000000001';
  if(v.page==='preview') {
   browser.check(v.text.includes('Confirmation rechecks every original pilot device')&&v.text.includes('within the last 24 hours')&&v.text.includes('Notification acknowledgments and deadline timing do not determine readiness'),'Pilot requirements or confirmation boundary missing');
   browser.check(v.text.includes('not managed through native Apple MDM'),'Destination exclusion is hidden');
  }
  if(state==='plans')browser.check(v.plans.length===3&&v.plans[0].links===1&&v.plans.slice(1).every(p=>p.links===0),'Archived or different-target plan is selectable');
  if(state==='groups')browser.check(v.links.filter(a=>a.text==='Review pilot and destination').length===1&&v.links.some(a=>a.href.includes('group_revision=3')&&a.href.includes('destination_plan=30000000-0000-4000-8000-000000000002')),'Group choice lost destination or group revision');
  if(state==='empty-plans')browser.check(v.text.includes('No update plans on this page'),'Empty plan page invents destination');
  if(state==='empty-groups')browser.check(v.text.includes('No dynamic groups on this page'),'Empty group page invents destination');
  if(['overlap','long'].includes(state))browser.check(v.targets===2&&v.text.includes('Overlapping pilot devices are included')&&v.text.includes('Existing policy will be replaced'),'Overlapping pilot policies are silently excluded');
  const reason={unknown:'usable, fresh OS report',stale:'more than 24 hours old',error:'current policy reports an error',exception:'temporary update exception is active','post-exception':'after the latest exception ended','different-policy':'policy values differ',unavailable:'original enrollment is unavailable',incompatible:"destination must use the original pilot's platform",'pilot-only':'at least one eligible destination device must be outside'}[state];
  if(reason)browser.check(v.text.includes(reason),'Promotion block reason is missing');
  if(state==='unavailable')browser.check(!v.links.some(a=>a.text==='Open current device state'),'Unavailable pilot leaks a current device link');
  if(['receipt','receipt-site-operator'].includes(state))browser.check(v.proofs===1&&v.text.includes('immutable receipt')&&v.text.includes('does not establish destination installation')&&v.text.includes('Latest exception ended')&&v.links.some(a=>a.text==='Open current destination progress'&&a.href.includes('/30000000-0000-4000-8000-000000000002/group-assignments/40000000-0000-4000-8000-000000000002/progress')),'Receipt loses original evidence or destination scope');
  if(state==='history')browser.check(v.links.some(a=>a.text==='Older promotions'&&a.href===base+'/promotions?before=50000000-0000-4000-8000-000000000001'),'Promotion history cursor changed');
  if(state==='empty-history')browser.check(v.text.includes('No confirmed promotions')&&!v.links.some(a=>a.text==='Older promotions'),'Empty history invents receipt');
  if(organization) {
   if(v.page==='groups') {
    browser.check(v.text.includes('only within the selected target site'),'Organization group choice lost target-site boundary');
    const choices=v.links.filter(a=>a.text==='Review pilot and destination');
    browser.check(choices.every(a=>new URL(a.href,'http://owned.invalid').searchParams.get('source')==='organization'),'Review link lost organization source');
    browser.check(v.links.some(a=>a.text==='Organization groups'&&a.href.includes('source=organization'))&&v.links.some(a=>a.text==='Site groups'&&!a.href.includes('source=organization')),'Destination source navigation is missing');
    browser.check(v.links.some(a=>a.href.includes('after=20000000-0000-4000-8000-000000000002')&&a.href.includes('source=organization')),'Group paging lost organization source');
   } else if(v.page==='history') {
    browser.check(v.text.includes('Source: organization group · Target site: 1'),'History lost promotion source kind');
   } else {
    browser.check(v.text.includes("Only the selected target site's members are included"),'Promotion lost organization source boundary');
    const links=v.links.filter(a=>a.text==='Open the current organization group and its history');
    browser.check(links.length===(['receipt-site-operator','preview-site-operator'].includes(state)?0:1)&&links.every(a=>a.href==='/tenant/1/device-groups/20000000-0000-4000-8000-000000000001'),'Source link bypasses current organization rights or uses wrong scope');
    browser.check(!v.links.some(a=>a.href==='/tenant/1/site/1/device-groups/20000000-0000-4000-8000-000000000001'),'Organization group resolved under target site');
   }
  }
  if(editable) {
   const f=v.forms[0],fields=f.fields;
   browser.check(f.required&&f.action===base+'/promotions'&&fields.csrf==='owned-csrf'&&fields.group_source===(organization?'organization':'site')&&fields.destination_plan==='30000000-0000-4000-8000-000000000002'&&fields.expected_revision==='2'&&fields.group_id==='20000000-0000-4000-8000-000000000001'&&fields.group_revision==='3'&&fields.request_key==='60000000-0000-4000-8000-000000000001','Promotion form lost immutable reviewed intent or scope');
   const expected=['10000000-0000-4000-8000-000000000002:'+ 'b'.repeat(64)];
   if(['overlap','long'].includes(state))expected.push('10000000-0000-4000-8000-000000000001:'+ 'a'.repeat(64));
   browser.check(JSON.stringify(fields.devices.split('\n').sort())===JSON.stringify(expected.sort()),'Promotion lost exact reviewed policy tokens');
   browser.check(fields.devices.split('\n').length===v.targets&&!('confirmed' in fields),'Destination selection or initial confirmation changed');
   await browser.evaluate(`(()=>{window.promotionSubmissions=[];document.querySelector('[data-promotion-confirm]').addEventListener('submit',e=>{e.preventDefault();window.promotionSubmissions.push(Object.fromEntries(new FormData(e.target,e.submitter)))});document.querySelector('[data-promotion-confirm] button').focus()})()`);await browser.enter();
   browser.check(await browser.evaluate('window.promotionSubmissions.length')===0,'Unconfirmed promotion submitted');
   await browser.evaluate("document.querySelector('[data-promotion-confirm]').elements.confirmed.focus()");await browser.space();await browser.tab();await browser.enter();
   const submitted=await browser.evaluate('window.promotionSubmissions');
   browser.check(submitted.length===1&&submitted[0].confirmed==='yes'&&Object.entries(fields).every(([k,value])=>submitted[0][k]===value),'Keyboard promotion lost exact reviewed selection');
  }
  if(width===390){await browser.evaluate("document.querySelector('[data-update-promotion-page]').scrollIntoView({block:'start'})");await browser.capture('apple-update-promotion-'+fixture+'-390');}
  record({name:'Apple update promotion '+fixture,width,passed:true});
 }
}
