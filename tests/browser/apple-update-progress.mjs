export default async function run(browser,record) {
 for(const state of ['reported','required','unverified','different','removed','unavailable','attention','mixed','long'])for(const width of [390,768,1440]){
  await browser.visit('apple-update-progress-'+state,width);
  const view=await browser.evaluate(`(()=>{
   const main=document.querySelector('[data-update-group-progress]');
   return {width:document.documentElement.scrollWidth,viewport:innerWidth,text:main.textContent,forms:main.querySelectorAll('form').length,devices:[...main.querySelectorAll('[data-update-progress-device]')].map(e=>({id:e.dataset.updateProgressDevice,text:e.textContent,links:[...e.querySelectorAll('a')].map(a=>a.getAttribute('href'))})),os:main.querySelector('[data-update-progress-counts]').textContent,policy:main.querySelector('[data-update-policy-counts]').textContent,links:[...main.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))};
  })()`);
  browser.check(view.width<=view.viewport+1,'Apple cohort progress overflows viewport');
  browser.check(view.forms===0&&view.devices.length===(state==='mixed'?2:1),'Progress page offers mutation or changes original selection');
  browser.check(view.text.includes('OS observations and current configured policy are evaluated separately')&&view.text.includes('does not establish installation'),'Progress confuses declaration delivery with OS evidence');
  browser.check(view.links.some(a=>a.text==='Refresh this assessment'&&a.href==='/tenant/1/site/1/ios/update-plans/70000000-0000-0000-0000-000000000001/group-assignments/40000000-0000-0000-0000-000000000001/progress'),'Progress refresh changes scope or original receipt');
  const first=view.devices[0];browser.check(first.id==='10000000-0000-0000-0000-000000000001','Progress changed original native ID');
  if(['reported','different','removed','attention','mixed','long'].includes(state))browser.check(view.os.includes('Target or newer OS reported: 1')&&first.text.includes('Reported OS: 18.7.1'),'Fresh target report lost independent OS outcome');
  if(state==='required')browser.check(view.os.includes('Update still required: 1')&&first.text.includes('18.6.2'),'Required update hidden');
  if(state==='unverified')browser.check(view.os.includes('Result unverified: 1')&&first.text.includes('build was not reported together'),'Incomplete build treated as verified');
  if(state==='different')browser.check(view.policy.includes('Different configured policy: 1')&&first.text.includes('2026-11-01T18:00:00')&&first.text.includes('A different update policy'),'Replacement policy not distinguished from reported target');
  if(state==='removed')browser.check(view.policy.includes('No configured update policy: 1')&&first.text.includes('No update policy is currently configured'),'Removed policy still presented as active');
  if(state==='unavailable')browser.check(first.links.length===0&&first.text.includes('Original notification: Unavailable')&&!first.text.includes('Reported OS:')&&view.policy.includes('Original enrollment unavailable: 1'),'Unavailable original enrollment exposes current device details');
  if(state==='attention')browser.check(view.policy.includes('Matching policy needs attention: 1')&&first.text.includes('Failure reported')&&first.text.includes('Open the device to review'),'Policy error lost or counted as installation failure');
  if(state==='mixed')browser.check(view.os.includes('Result unverified: 1')&&view.policy.includes('No configured update policy: 1'),'Mixed cohort counts collapsed independent states');
  if(width===390){await browser.evaluate("document.querySelector('[data-update-progress-device]').scrollIntoView({block:'center'})");await browser.capture('apple-update-progress-'+state+'-390');}
  record({name:'Apple cohort progress '+state,width,passed:true});
 }
}
