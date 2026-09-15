export default async function run(browser, record) {
  const base = '/tenant/1/netbird/packages';
  const id = '10000000-0000-4000-8000-000000000001';
  const fill = `document.querySelector('#netbird-package-target').value='linux/arm64/deb';document.querySelector('#netbird-package-version').value='0.78.1';document.querySelector('#netbird-package-source').value='https://packages.example.invalid/netbird.deb?private=owned-source';document.querySelector('#netbird-package-size').value='1234';document.querySelector('#netbird-package-sha256').value='a'.repeat(64);document.querySelector('#netbird-package-verification').value='Owned publisher review 42';`;
  for (const width of [390, 768, 1440]) {
    for (const kind of ['new', 'empty', 'list', 'list-viewer', 'detail', 'detail-viewer', 'revoked', 'long']) {
      await browser.visit('netbird-packages-' + kind, width);
      browser.check(await browser.evaluate(`document.documentElement.scrollWidth<=innerWidth+1 && document.querySelector('#netbird-packages').getAttribute('hx-history')==='false' && document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`), 'Package approval page overflows, retains private history or repeats IDs');
      browser.check(!await browser.evaluate(`!!document.querySelector('Berlin') || document.body.textContent.includes('@mdm_views') || document.body.textContent.includes('MISSING')`), 'Package approval metadata became markup or template source');
      if (kind === 'empty') browser.check(await browser.evaluate(`document.body.textContent.includes('No package approvals are stored.')`), 'Empty package history implies an approval');
      if (kind === 'list' || kind === 'list-viewer') {
        browser.check(await browser.evaluate(`document.querySelector('#netbird-package-next').getAttribute('href')==='${base}?after=${id}' && !!document.querySelector('#netbird-package-new')===${kind === 'list'}`), 'Package history loses its scoped cursor or exposes approval to a reader');
      }
      if (kind === 'detail-viewer' || kind === 'revoked') browser.check(!await browser.evaluate(`!!document.querySelector('#netbird-package-revoke')`), 'Package history permits revocation without authority or after revocation');
      if (kind === 'revoked') browser.check(await browser.evaluate(`document.querySelector('#netbird-package-status').textContent.trim()==='Revoked'`), 'Revoked approval is presented as usable');
      if (kind === 'new' || kind === 'detail') {
        if (kind === 'new') {
          browser.check(await browser.evaluate(`document.querySelector('#netbird-package-source').value==='' && document.querySelector('#netbird-package-source').autocomplete==='off' && document.querySelector('#netbird-package-target').options.length===9`), 'Approval form preloads a private source or omits supported targets');
          await browser.evaluate(fill);
        }
        await browser.evaluate(`window.packageRequest=null;document.body.addEventListener('htmx:configRequest',e=>{packageRequest={path:e.detail.path,fields:[...e.detail.formData.entries()]};e.preventDefault()});document.querySelector('#netbird-package-submit').focus()`);
        await browser.enter();
        browser.check(await browser.evaluate('packageRequest===null'), 'Package approval action submitted without explicit confirmation');
        await browser.evaluate(`document.querySelector('#netbird-package-confirm').checked=true;document.querySelector('#netbird-package-submit').focus()`);
        await browser.enter();
        const request = await browser.evaluate('packageRequest');
        const fields = request && Object.fromEntries(request.fields);
        browser.check(fields?.csrf === 'owned-netbird-csrf' && fields.confirmed === 'yes', 'Package action loses CSRF or confirmation');
        if (kind === 'new') browser.check(request.path === base && request.fields.length === 9 && fields.approval_id === id && fields.target === 'linux/arm64/deb' && fields.source_url.endsWith('?private=owned-source') && fields.size === '1234' && fields.sha256 === 'a'.repeat(64), 'Approval changed exact package intent or scope');
        else browser.check(request.path === base + '/' + id + '/revoke' && request.fields.length === 4 && fields.digest === 'b'.repeat(64) && fields.request_id === '20000000-0000-4000-8000-000000000002', 'Revocation loses the reviewed approval or request identity');
      }
      if (width === 390 && ['new', 'detail', 'long'].includes(kind)) await browser.capture('netbird-packages-' + kind + '-390');
      record({ name: 'NetBird packages ' + kind, width, passed: true });
    }
    for (const kind of ['new', 'detail']) {
      await browser.visit('netbird-packages-' + kind, width);
      if (kind === 'new') await browser.evaluate(fill);
      await browser.evaluate(`window.packageXHR=null;window.packageSends=0;XMLHttpRequest.prototype.send=function(){packageXHR=this;packageSends++};document.querySelector('#netbird-package-confirm').checked=true;document.querySelector('#netbird-package-submit').focus()`);
      await browser.enter();
      browser.check(await browser.evaluate(`packageSends===1 && document.querySelector('#netbird-package-submit').matches(':disabled') && document.querySelector('#netbird-package-confirm').matches(':disabled') && getComputedStyle(document.querySelector('#netbird-package-pending')).opacity==='1'`), 'Pending package action leaves controls active or hides progress');
      await browser.evaluate(`document.querySelector('#netbird-package-submit').form.requestSubmit()`);
      browser.check(await browser.evaluate('packageSends===1'), 'Pending package action was sent twice');
      await browser.evaluate(`(()=>{const xhr=packageXHR;Object.defineProperties(xhr,{status:{value:204},response:{value:''},responseText:{value:''},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
      browser.check(await browser.evaluate(`!document.querySelector('#netbird-package-submit').matches(':disabled')`), 'Package action controls did not recover after the response');
      record({ name: 'NetBird packages ' + kind + ' pending controls', width, passed: true });
    }
  }
}
