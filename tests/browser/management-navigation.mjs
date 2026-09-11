export default async function run(browser, record) {
  const {visit,evaluate,check,enter,space,tab,capture}=browser;
  for(const role of ['viewer','operator','organization_admin','administrator'])
    for(const width of [390,768,1440]){
      await visit('management-navigation-'+role,width);
      const initial=await evaluate(`(()=>{
        window.navigation=document.querySelector('nav[aria-label="Management pages"]');window.disclosure=navigation.closest('details');window.summary=disclosure.querySelector('summary');
        return {open:disclosure.open,height:disclosure.getBoundingClientRect().height,summary:summary.textContent,card:document.querySelector('#device-management > section').getBoundingClientRect().top};
      })()`);
      check(!initial.open && initial.height<=72 && initial.summary==='Management pages' && initial.card<700,'Closed management navigation hides the device content or is not compact');
      await evaluate('summary.focus()');
      await enter();
      const opened=await evaluate(`(()=>{
        const style=getComputedStyle(summary);
        return {open:disclosure.open,focus:document.activeElement===summary,outline:style.outlineStyle,width:parseFloat(style.outlineWidth),
          links:Array.from(navigation.querySelectorAll('a'),a=>({text:a.textContent,path:new URL(a.href).pathname,visible:a.getBoundingClientRect().width>0}))};
      })()`);
      check(opened.open && opened.focus,'Keyboard could not open native management navigation');
      check(opened.outline!=='none' && opened.width>0,'Keyboard disclosure focus is not visible');
      const expected={
        'Approved software':'/software/catalog','All devices':'/devices','Apple profiles':'/ios/configurations',
        'Apple setup and enrollment':'/ios/setup','Desktop enrollment':'/desktop/enrollment','Native Windows management':'/windows',
      };
      if(role==='administrator'){
        expected['Windows software deployment']='/deploy';expected['Windows profiles']='/profiles';
      }
      if(role==='administrator'||role==='organization_admin')expected['Automated Device Enrollment']='/ios/ade';
      check(opened.links.length===Object.keys(expected).length && opened.links.every(a=>a.visible && a.path==='/tenant/1/site/1'+expected[a.text]),'Management links changed permission, visibility or scope: '+JSON.stringify(opened.links));
      await tab();
      check(await evaluate('document.activeElement===navigation.querySelector("a")'),'Expanded navigation is not reachable with Tab');
      check(await evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Expanded management navigation or device table overflow');
      if(width===390 && role==='administrator')await capture('management-navigation-expanded-390');
      await evaluate('summary.focus()');
      await space();
      check(await evaluate('!disclosure.open && document.activeElement===summary'),'Space could not close navigation while retaining focus');
      check(await evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Collapsed management navigation or device table overflow');
      if(width===390 && role==='administrator')await capture('management-navigation-collapsed-390');
      record({name:'Management navigation '+role,width,passed:true});
    }
}
