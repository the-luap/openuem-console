export default async function run(browser, record) {
  for (const state of ['preview','empty','different','mixed','unavailable','no-notification','receipt','receipt-no-notification','history','empty-history','long']) {
    for (const width of [390,768,1440]) {
      await browser.visit('apple-update-removal-'+state,width);
      const view=await browser.evaluate(`(()=>{
        const main=document.querySelector('[data-update-group-removal]');
        window.removalForm=main.querySelector('[data-update-removal-confirm]');
        return {width:document.documentElement.scrollWidth,viewport:innerWidth,text:main.textContent,form:!!removalForm,
          action:removalForm?.getAttribute('action'),devices:[...main.querySelectorAll('[data-update-removal-device]')].map(d=>({id:d.dataset.updateRemovalDevice,text:d.textContent,links:d.querySelectorAll('a').length})),
          links:[...main.querySelectorAll('a')].map(a=>a.getAttribute('href'))};
      })()`);
      const base='/tenant/1/site/1/ios/update-plans/70000000-0000-0000-0000-000000000001/group-assignments/40000000-0000-0000-0000-000000000001';
      browser.check(view.width<=view.viewport+1,'Group policy removal overflows viewport');
      if(!state.includes('history')) browser.check(view.text.includes('Original update plan:')&&!view.text.includes('Available plan'),'Original plan was presented as current availability');
      browser.check(view.links.every(a=>a.startsWith('/tenant/1/site/1/ios/')),'Removal navigation lost its original scope');
      const actionable=['preview','mixed','no-notification','long'].includes(state);
      browser.check(view.form===actionable,'Removal confirmation does not match reviewed eligibility');
      if(actionable){
        browser.check(view.action===base+'/removals','Removal form changed original assignment');
        await browser.evaluate(`removalForm.addEventListener('submit',e=>{e.preventDefault();window.removalFields=Object.fromEntries(new FormData(removalForm,e.submitter));});removalForm.querySelector('button[type="submit"]').focus()`);
        await browser.enter();
        browser.check(await browser.evaluate('!window.removalFields'),'Removal bypassed explicit confirmation');
        await browser.evaluate('removalForm.elements.confirmed.focus()');
        await browser.space();
        await browser.evaluate('removalForm.querySelector(\'button[type="submit"]\').focus()');
        await browser.enter();
        const fields=await browser.evaluate('window.removalFields');
        browser.check(fields.confirmed==='yes'&&fields.csrf==='owned-csrf'&&fields.request_key==='50000000-0000-0000-0000-000000000001','Removal keyboard submission lost confirmation, CSRF or request identity');
        browser.check(fields.devices==='10000000-0000-0000-0000-000000000001:'+ 'b'.repeat(64),'Removal included excluded devices or changed its reviewed policy');
      }
      if(view.devices.length)browser.check(view.devices.length===(state==='mixed'?2:1),'Removal changed original cohort');
      if(state==='empty')browser.check(view.text.includes('no configured update policy to remove'),'Absent policy is not explained');
      if(state==='different')browser.check(view.text.includes('different configured update policy')&&view.text.includes('2026-11-01T18:00:00'),'Replacement policy is not distinguished');
      if(state==='unavailable')browser.check(view.devices[0].links===0&&!view.devices[0].text.includes('Owned')&&view.text.includes('Current device details are withheld'),'Moved enrollment exposed current metadata');
      if(state==='no-notification')browser.check(view.text.includes('cannot currently send a declarative notification')&&view.text.includes('device-side removal remains unverified'),'Unavailable delivery lacks explicit review warning');
      if(state.startsWith('receipt'))browser.check(view.text.includes('Later policy changes do not alter this receipt')&&view.links.includes(base+'/progress'),'Receipt lost original evidence or current progress navigation');
      if(state==='receipt-no-notification')browser.check(view.text.includes('No declarative notification was available'),'Receipt invented a notification');
      if(state==='history')browser.check(view.links.includes(base+'/removals?before=60000000-0000-0000-0000-000000000001'),'Removal pagination changed its cursor scope');
      if(state==='empty-history')browser.check(view.text.includes('No policy removal requests are recorded'),'Empty removal history is ambiguous');
      if(width===390)await browser.capture('apple-update-removal-'+state+'-390');
      record({name:'Apple update removal '+state,width,passed:true});
    }
  }
}
