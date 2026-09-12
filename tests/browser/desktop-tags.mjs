export default async function run(browser, record) {
  for (const width of [390, 768, 1440]) {
    await browser.visit('desktop-tag-actions', width);
    await browser.evaluate(`document.body.addEventListener('htmx:configRequest', e => {
      const d=e.detail;
      window.tagRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};
      e.preventDefault();
    })`);
    const paths=['/tenant/1/site/2/agents','/tenant/1/site/2/computers','/tenant/1/admin/update-agents'];
    for (let i=0;i<paths.length;i++) {
      for (const method of i===2?['delete']:['post','delete']) {
        await browser.evaluate(`window.tagRequest=null;document.querySelector('#tag-action-${i} button[hx-${method}]').focus()`);
        await browser.enter();
        const r=await browser.evaluate('tagRequest');
        browser.check(r && r.method===method && r.path===paths[i], 'Tag action lost its method or scope');
        browser.check(r.query===(method==='delete'), 'Tag action changed the bundled HTMX query/body protocol');
        browser.check(r.headers['X-CSRF-Token']==='owned-csrf', 'Tag action lost its CSRF header');
        browser.check(r.fields.agentId==='owned-agent' && r.fields.tagId==='42', 'Tag action lost its target identity');
        browser.check(r.fields.page==='2' && r.fields.pageSize==='25' && r.fields.sortBy==='hostname' && r.fields.sortOrder==='asc' && r.fields.filterByOs==='windows' && r.fields.filterByTag7==='on', 'Tag action lost its pagination or filter context');
      }
      record({name:'Desktop tag HTMX '+paths[i],width,passed:true});
    }
  }
}
