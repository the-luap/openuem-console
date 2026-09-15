export async function checkCurrentLink(browser, label, expected) {
  const nav = await browser.evaluate(`(() => {
    const nav=Array.from(document.querySelectorAll('nav')).find(n=>n.getAttribute('aria-label')===${JSON.stringify(label)});
    if(!nav) throw Error('Inventory navigation missing');
    return Array.from(nav.querySelectorAll('a'),a=>({text:a.textContent,current:a.getAttribute('aria-current'),primary:a.classList.contains('uk-button-primary'),
      ordinary:a.classList.contains('uk-button-default'),decoration:getComputedStyle(a).textDecorationLine,background:getComputedStyle(a).backgroundColor}));
  })()`);
  const current=nav.filter(a=>a.current==='page');
  browser.check(current.length===1 && current[0].text===expected && current[0].primary && !current[0].ordinary && current[0].decoration.includes('underline'),"Active inventory link lacks its visible and accessible indication");
  browser.check(nav.filter(a=>a.current!=='page').every(a=>!a.primary && a.ordinary && a.background!==current[0].background),"Inactive inventory links appear selected");
}
