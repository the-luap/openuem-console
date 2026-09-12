export function checkDeadline(browser,state,deadline,original) {
  if(state==='no-policy') {
    browser.check(!deadline,'Absent policy retained a deadline estimate');
    return;
  }
  browser.check(!!deadline,'Deadline assessment is missing');
  browser.check(deadline.text.includes(original?'Original deadline estimate':'Current policy deadline estimate'),'Deadline estimate lost its policy source');
  browser.check(deadline.text.includes('last reported device time zone')&&deadline.text.includes('OS evidence is assessed separately'),'Deadline estimate lacks its evidence limits');
  if(state==='deadline-pending'||state==='deadline-fold')browser.check(deadline.state==='pending','Pending deadline treated as elapsed');
  else if(state==='deadline-elapsed')browser.check(deadline.state==='elapsed','Elapsed deadline hidden');
  else browser.check(deadline.state==='unverified'&&!deadline.text.includes('Estimated deadline (UTC):')&&!deadline.text.includes('Possible deadline range'),'Unknown timing invented a deadline instant');
  if(state==='deadline-fold')browser.check(deadline.text.includes('2026-10-25 00:30:00 to 2026-10-25 01:30:00')&&deadline.text.includes('only at the latest possible instant'),'Repeated local hour lost its conservative range');
  if(state==='deadline-gap')browser.check(deadline.text.includes('skipped hour')&&deadline.text.includes('Europe/Berlin'),'Nonexistent local time lacks explanation');
  if(state==='deadline-stale')browser.check(deadline.text.includes('more than 24 hours old'),'Stale time zone appears current');
  if(state==='deadline-future')browser.check(deadline.text.includes('later than this assessment'),'Future time zone appears current');
  if(state==='deadline-invalid')browser.check(deadline.text.includes('cannot be resolved')&&deadline.text.includes('<script>'),'Invalid zone escaped or explained incorrectly');
  if(state.startsWith('deadline-'))browser.check(deadline.text.includes('Time zone recorded from Device Information (UTC):'),'Time zone source or timestamp is missing');
  if(state==='unavailable')browser.check(!deadline.text.includes('Reported device time zone:'),'Moved enrollment exposed time zone evidence');
}
