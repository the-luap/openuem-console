export default async function run(browser,record) {
  for(const width of [390,768,1440]) {
    await browser.visit('tag-color-compatibility',width);
    const view=await browser.evaluate(`(()=>{
      const collect=selector=>Array.from(document.querySelectorAll(selector),node=>{const s=getComputedStyle(node);return {background:s.backgroundColor,color:s.color,text:node.textContent.trim()}});
      return {readonly:collect('#read-only-tags span'),remove:collect('#removable-tags button'),available:collect('#available-tags form div.rounded-full'),width:document.documentElement.scrollWidth,viewport:innerWidth,scripts:document.querySelectorAll('script').length};
    })()`);
    const names=['red','orange','amber','yellow','lime','green','emerald','teal','cyan','sky','blue','indigo','violet','purple','fuchsia','pink','rose','gray','stone'];
    const rgb=['239, 68, 68','249, 115, 22','245, 158, 11','234, 179, 8','132, 204, 22','34, 197, 94','16, 185, 129','20, 184, 166','6, 182, 212','14, 165, 233','59, 130, 246','99, 102, 241','139, 92, 246','168, 85, 247','217, 70, 239','236, 72, 153','244, 63, 94','107, 114, 128','120, 113, 108','171, 193, 35','255, 255, 255','0, 0, 0','107, 114, 128'];
    const luminance=color=>{const [r,g,b]=color.match(/\d+/g).slice(0,3).map(v=>{v=Number(v)/255;return v<=0.04045?v/12.92:((v+0.055)/1.055)**2.4});return r*.2126+g*.7152+b*.0722};
    for(const kind of ['readonly','remove','available']) {
      browser.check(view[kind].length===rgb.length,'A shared tag color fixture is missing: '+kind);
      view[kind].forEach((row,index)=>{
        browser.check(row.background==='rgb('+rgb[index]+')','Shared tag color changed: '+kind+'/'+(names[index]||index));
        if(kind!=='available') {
          const a=luminance(row.background),b=luminance(row.color);
          browser.check((Math.max(a,b)+.05)/(Math.min(a,b)+.05)>=4.5,'Tag label contrast is insufficient: '+kind+'/'+index);
        }
      });
    }
    browser.check(view.width<=view.viewport+1 && view.scripts===0,'Tag colors or long labels overflow or become active content');
    if(width===390)await browser.capture('tag-color-compatibility-390');
    record({name:'Shared tag palette and custom colors',width,passed:true});
  }
}
