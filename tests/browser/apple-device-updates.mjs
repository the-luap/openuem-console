export default async function run(browser, record) {
  for (const state of ['required', 'compliant', 'missing-build', 'stale', 'unmanaged', 'error', 'error-limited', 'no-policy', 'viewer', 'long', 'missing']) {
    for (const width of [390, 768, 1440]) {
      await browser.visit('apple-device-update-' + state, width);
      const view = await browser.evaluate(`(() => {
        const main = document.querySelector('[data-device-update-assessment]');
        return {width:document.documentElement.scrollWidth, viewport:innerWidth, text:main.textContent,
          evidence:main.querySelector('[data-device-update-evidence]').textContent,
          policy:main.querySelector('[data-device-update-policy]')?.textContent,
          scripts:main.querySelectorAll('script').length,
          forms:[...main.querySelectorAll('form')].map(f=>({action:f.getAttribute('action'),csrf:f.elements.csrf?.value}))};
      })()`);
      browser.check(view.width <= view.viewport + 1, 'Device update assessment overflows viewport');
      browser.check(!view.evidence.includes('22F999') && !view.evidence.includes('18.5'), 'Update evidence borrowed merged inventory');
      browser.check(view.evidence.includes('unrelated status messages do not refresh its timestamp'), 'Packet evidence explanation is missing');
      browser.check(view.scripts === 0, 'Policy error created executable markup');
      if (state === 'missing') browser.check(view.evidence.includes('No usable OS observation') && !view.evidence.includes('Version recorded:'), 'Missing evidence fell back to inventory');
      else browser.check(view.evidence.includes('Version recorded:') && view.evidence.includes('Declarative status'), 'OS report time or source is missing');
      if (state === 'missing-build') browser.check(view.policy.includes('build was not reported together') && !view.evidence.includes('22H100'), 'Missing build was shown as a complete pair');
      if (state === 'stale') browser.check(view.policy.includes('more than 24 hours old') && !view.policy.includes('Up to date'), 'Stale report counted as current compliance');
      if (state === 'unmanaged') browser.check(view.policy.includes('inactive or its device identity has expired') && view.forms.length === 0, 'Inactive device has actionable or verified result');
      if (['compliant','error','error-limited','viewer','long'].includes(state)) browser.check(view.policy.includes('Up to date'), 'Policy state displaced independent reported OS result');
      if (state === 'error') browser.check(view.policy.includes('Owned <script>policy failure</script>') && view.policy.includes('Failed'), 'Escaped policy error or independent delivery state is missing');
      if (state === 'error-limited') browser.check(view.policy.includes('exceed the display limit'), 'Oversized error lost its bounded notice');
      if (state === 'required') browser.check(view.policy.includes('Update required') && view.evidence.includes('18.6.2'), 'Lower reported version lost required result');
      if (state === 'no-policy') browser.check(!view.policy && view.evidence.includes('18.7.1'), 'Policy removal hid OS evidence');
      if (state === 'viewer') browser.check(view.forms.length === 0, 'Read-only viewer can submit update changes');
      else if (state !== 'unmanaged') browser.check(view.forms.length === (state === 'no-policy' ? 1 : 2), 'Update action availability changed');
      browser.check(view.forms.every(f => f.action === '/tenant/1/site/1/ios/10000000-0000-0000-0000-000000000001/update' && f.csrf === 'owned-csrf'), 'Update form lost scope or CSRF');
      if (width === 390) {
        await browser.evaluate("document.querySelector('[data-device-update-assessment]').scrollIntoView({block:'start'})");
        await browser.capture('apple-device-update-' + state + '-390');
      }
      record({name:'Apple device update ' + state, width, passed:true});
    }
  }
}
