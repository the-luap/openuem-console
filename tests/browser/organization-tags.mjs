export default async function run(browser, record) {
  for (const state of ['list','empty','detail','used','viewer','long','list-viewer','administrator']) {
    for (const width of [390,768,1440]) {
      await browser.visit('organization-tags-'+state,width);
      const creating=['list','empty','list-viewer'].includes(state);
      const view=await browser.evaluate(`(()=>{
        window.tagRoot=document.querySelector('main[id^="organization-tag"]');
        window.tagForm=tagRoot.querySelector('form[aria-label="Edit tag"]');
        window.tagDelete=tagRoot.querySelector('form[aria-label="Delete tag"]');
        window.tagSearch=tagRoot.querySelector('form[aria-label="Search tags"]');
        return {form:!!tagForm,remove:!!tagDelete,search:!!tagSearch,revision:tagForm?.elements.revision?.value,
          path:tagForm?new URL(tagForm.action).pathname:null,method:tagForm?.method,articles:tagRoot.querySelectorAll('article').length,
          scripts:tagRoot.querySelectorAll('script').length,width:document.documentElement.scrollWidth,viewport:innerWidth};
      })()`);
      browser.check(view.form===!state.includes('viewer'),'Tag editor disagrees with whole-organization permission');
      browser.check(view.remove===(state==='detail'||state==='long'||state==='administrator'),'Used or read-only tag exposes deletion');
      browser.check(view.search===creating && view.articles===(creating&&state!=='empty'?1:0),'Tag list state changed');
      browser.check(view.scripts===0 && view.width<=view.viewport+1,'Tag text became script content or overflows');
      browser.check(await browser.evaluate(`getComputedStyle(tagRoot.querySelector('h1')).color===getComputedStyle(document.querySelector('header')).color`),'Tag heading lost the active theme foreground');
      browser.check(await browser.evaluate(`!!document.querySelector('option[value="/admin"]')===${state==='administrator'} && !!tagRoot.querySelector('a[href="/tenant/1/admin/settings"]')===${state==='administrator'} && !document.querySelector('select[name="site"]') && !document.querySelector('#console-header-controls').textContent.includes('Berlin')`),'Organization tag navigation lost administrator settings or exposes an unauthorized scope');
      if(view.form) {
        browser.check(view.method==='post' && view.path==='/tenant/1/admin/tags'+(creating?'':'/42'),'Tag action lost its organization scope');
        browser.check(creating?view.revision===undefined:view.revision==='00000000-0000-4000-8000-000000000042','Tag edit lost the reviewed generation');
        await browser.evaluate(`tagForm.elements.name.value='Keyboard tag';tagForm.elements.description.value='Reviewed definition';tagForm.elements.color.value='#abcdef';tagForm.addEventListener('submit',e=>{e.preventDefault();window.tagFields=Object.fromEntries(new FormData(tagForm,e.submitter))});tagForm.querySelector('button').focus()`);
        await browser.enter();
        const fields=await browser.evaluate('tagFields');
        browser.check(fields.csrf==='owned-csrf' && fields.name==='Keyboard tag' && fields.description==='Reviewed definition' && fields.color==='#abcdef','Keyboard tag edit lost form values or CSRF');
      }
      if(view.remove) {
        browser.check(await browser.evaluate('!tagDelete.checkValidity()'),'Deletion lacks explicit native confirmation');
        await browser.evaluate(`tagDelete.addEventListener('submit',e=>{e.preventDefault();window.tagDeleteFields=Object.fromEntries(new FormData(tagDelete,e.submitter))});tagDelete.elements.confirm.focus()`);
        await browser.space();
        await browser.evaluate(`tagDelete.querySelector('button').focus()`);
        await browser.enter();
        const fields=await browser.evaluate('tagDeleteFields');
        browser.check(fields.confirm==='delete' && fields.csrf==='owned-csrf' && fields.revision==='00000000-0000-4000-8000-000000000042','Keyboard delete lost confirmation or reviewed generation');
      }
      if(view.search) {
        await browser.evaluate(`tagSearch.addEventListener('submit',e=>{e.preventDefault();window.tagQuery=Object.fromEntries(new FormData(tagSearch,e.submitter))});tagSearch.querySelector('button').focus()`);
        await browser.enter();
        browser.check((await browser.evaluate('tagQuery')).q==='Owned','Keyboard search lost its query');
        browser.check(await browser.evaluate(`(()=>{const a=tagRoot.querySelector('nav[aria-label="Tag pages"] a');const u=new URL(a.href);return u.pathname==='/tenant/1/admin/tags' && u.searchParams.get('q')==='Owned' && u.searchParams.get('after')==='42'})()`),'Tag pagination lost organization or search');
      }
      if(width===390)await browser.capture('organization-tags-'+state+'-390');
      record({name:'Organization tags '+state,width,passed:true});
    }
  }
}
