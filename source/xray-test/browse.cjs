const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const challenge = /captcha|капч[аи]|провер[кь].{0,25}(робот|браузер)|verify you are human|checking your browser|access denied|доступ запрещ[её]н|just a moment|security check/i;
function targets(sites, required) {
  if (!Array.isArray(required) || !required.length) throw Error('Список обязательных сайтов пуст');
  const queue = new Map();
  function normalize(value) {
    const u = new URL(value.includes('://') ? value : 'https://'+value);
    if (!['https:','http:'].includes(u.protocol) || u.username || u.password) throw Error('Некорректный URL');
    u.hash = ''; return u.href;
  }
  for (const line of sites.split(/\r?\n/).map(s=>s.trim()).filter(s=>s && !s.startsWith('#'))) {
    const url = normalize(line); queue.set(url,{url,required:false});
  }
  for (const profile of required) {
    if (profile.statusOnly !== true) {
      if (!profile.text || !profile.selector) throw Error('Обязательному сайту нужны text и selector');
      new RegExp(profile.text,'i');
    }
    const url = normalize(profile.url); queue.set(url,{...profile,url,required:true});
  }
  return [...queue.values()];
}
async function pool(items, fn, count=10) {
  let next = 0;
  const results = new Array(items.length);
  await Promise.all(Array.from({length:Math.min(count,items.length)}, async()=>{
    while (next < items.length) { const i = next++; results[i] = await fn(items[i],i); }
  }));
  return results;
}
async function visit(browser, item, index, out, options={}) {
  const started = Date.now();
  const result = {url:item.url,required:item.required,started:new Date().toISOString(),ok:false};
  const context = await browser.newContext({ignoreHTTPSErrors:false,locale:'ru-RU',serviceWorkers:'block'});
  const page = await context.newPage();
  let failedResources = 0;
  page.on('requestfailed',()=>failedResources++);
  page.on('response',response=>{
    if(response.request().isNavigationRequest() && response.frame() === page.mainFrame()) result.status=response.status();
  });
  try {
    const timeout = options.timeout ?? 60000;
    const statusOnly = item.statusOnly === true;
    const response = await page.goto(item.url,{waitUntil:statusOnly?'commit':'domcontentloaded',timeout});
    result.status = response?.status();
    if (statusOnly) {
      if (result.status !== 200) throw Error('Главная страница: ожидался HTTP 200, получен '+(result.status ?? 'нет ответа'));
    } else {
      if (!response || result.status < 200 || result.status >= 300) throw Error('Главная страница: HTTP '+result.status);
      // A single deadline covers navigation and readiness, including SPA rendering.
      const remaining = () => Math.max(1, timeout - (Date.now()-started));
      await page.waitForFunction(() => document.body?.innerText.trim().length >= 40, null, {timeout:remaining()});
      if (challenge.test(await page.locator('body').innerText()) || challenge.test(await page.title())) throw Error('Страница защиты/капча вместо сайта');
      if (item.required) {
        await page.getByText(new RegExp(item.text,'i')).first().waitFor({state:'visible',timeout:remaining()});
        await page.locator(item.selector).filter({visible:true}).first().waitFor({state:'visible',timeout:remaining()});
      }
      const until = Date.now()+(options.dwell ?? 10000);
      while (Date.now()<until) {
        await page.evaluate(()=>window.scrollBy(0,Math.max(400,window.innerHeight * .8)));
        await page.waitForTimeout(Math.min(1000,until-Date.now()));
      }
      if (result.status < 200 || result.status >= 300) throw Error('Конечная страница: HTTP '+result.status);
      const body = await page.locator('body').innerText();
      if (challenge.test(body) || challenge.test(await page.title())) throw Error('Страница защиты/капча вместо сайта');
      if (body.trim().length < 40) throw Error('Пустая страница или незагрузившийся интерфейс');
      if (item.required) {
        if (!new RegExp(item.text,'i').test(body)) throw Error('Нет ожидаемого текста интерфейса');
        if (!await page.locator(item.selector).filter({visible:true}).count()) throw Error('Нет ожидаемого элемента интерфейса');
      }
    }
    result.ok = true;
  } catch (e) {
    result.error = e.message;
    try {await page.screenshot({path:path.join(out,`failure-${index}.png`),timeout:2000});} catch {}
  } finally {
    result.finalURL = page.url(); result.failedResources = failedResources;
    result.elapsedMs = Date.now()-started;
    await context.close();
  }
  console.log(`${item.required?'Обязательный':'Обычный'}: ${item.url}: ${result.ok?'OK':result.error}`);
  return result;
}
async function main() {
  const [sites,required,out,proxy] = process.argv.slice(2);
  if (!/^socks5:\/\/127\.0\.0\.1:\d+$/.test(proxy || '')) throw Error('Нужен SOCKS5 SSH tunnel на loopback');
  fs.mkdirSync(out,{recursive:true});
  const queue = targets(fs.readFileSync(sites,'utf8'),JSON.parse(fs.readFileSync(required,'utf8')));
  const browser = await chromium.launch({headless:true,proxy:{server:proxy},args:['--disable-quic','--proxy-bypass-list=<-loopback>']});
  let results;
  try {results=await pool(queue,(item,i)=>visit(browser,item,i,out));} finally {await browser.close();}
  const report = {sha:process.env.GITHUB_SHA,run:process.env.GITHUB_RUN_ID,finished:new Date().toISOString(),results};
  fs.writeFileSync(path.join(out,'sites.json'),JSON.stringify(report,null,2)+'\n');
  const failed = results.filter(r=>!r.ok);
  const summary = ['## Xray routing test',`Commit: ${report.sha || 'local'}`,`Завершено: ${report.finished}`,
    `Всего: ${results.length}; обязательных ошибок: ${failed.filter(r=>r.required).length}; предупреждений: ${failed.filter(r=>!r.required).length}`,
    '', '| Сайт | Обязательный | Результат | Время |','|---|---|---|---|',
    ...results.map(r=>`| ${r.url.replaceAll('|','%7C')} | ${r.required?'да':'нет'} | ${(r.ok?'OK':r.error).replaceAll('|','/').replaceAll('\n',' ')} | ${(r.elapsedMs/1000).toFixed(1)} с |`) ].join('\n')+'\n';
  fs.writeFileSync(path.join(out,'summary.md'),summary);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,summary);
  process.exitCode = failed.some(r=>r.required)?1:0;
}
if (require.main === module) main().catch(e=>{console.error(e);process.exitCode=1;});
module.exports={targets,pool,visit,challenge};
