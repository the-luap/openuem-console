export default async function run(browser, record) {
  for (const width of [390, 768, 1440]) {
    for (const kind of ['ordinary', 'duplicate', 'legacy', 'injected', 'empty', 'malformed']) {
      await browser.visit('netbird-profiles-' + kind, width);
      browser.check(await browser.evaluate(`document.documentElement.scrollWidth<=innerWidth+1 && document.querySelector('label[for="netbird-profile"]') && !document.querySelector('img') && !window.__netbirdInjected`), 'NetBird profile labels overflow, lack a label or become markup');
      const unavailable = ['empty', 'malformed'].includes(kind);
      browser.check(await browser.evaluate(`document.querySelector('#netbird-profile').disabled===${unavailable}`), 'Unavailable profile metadata remains selectable');
      if (!unavailable) {
        const expected = kind === 'legacy' ? 'home' : 'a1b2c3d4';
        await browser.evaluate(`window.profileRequest=null;document.querySelector('form').addEventListener('submit',event=>{event.preventDefault();profileRequest=[...new FormData(event.target)]});document.querySelector('#netbird-profile').selectedIndex=2;document.querySelector('#submit-profile').focus()`);
        await browser.enter();
        const fields = await browser.evaluate('profileRequest');
        browser.check(fields && fields.length === 1 && fields[0][0] === 'profile' && fields[0][1] === expected, 'Profile submission used a label or split a name instead of the exact handle');
        if (kind === 'duplicate') browser.check(await browser.evaluate(`document.querySelector('#netbird-profile').options[1].text==='office, with spaces (default)' && document.querySelector('#netbird-profile').options[2].text==='office, with spaces (a1b2c3d4)'`), 'Duplicate profile names cannot be distinguished');
      } else {
        browser.check(await browser.evaluate(`document.querySelector('[role="status"]').textContent.includes('Refresh the device status')`), 'Unavailable profile metadata lacks a recovery instruction');
      }
      record({name:'NetBird profile selection '+kind,width,passed:true});
      if(width===390 && ['duplicate','injected'].includes(kind)) await browser.capture('netbird-profiles-'+kind+'-390');
    }
  }
}
