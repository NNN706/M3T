"""Live cloud.vk.com opening test; bounded curl + real Chromium, no DNS/BGP."""
import argparse,json,os,pathlib,signal,subprocess,tempfile,urllib.parse
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');p.add_argument('--strict-preflight',action='store_true');args=p.parse_args()
source=args.script.read_text();helper=source[source.index('site_progress() {'):source.index('\nget_json()')]
url='https://cloud.vk.com/'
with tempfile.TemporaryDirectory(prefix='cloud-vk-live-') as directory:
 root=pathlib.Path(directory);artifact=pathlib.Path(os.environ.get('TEST_ARTIFACTS',directory));artifact.mkdir(parents=True,exist_ok=True)
 code='set -euo pipefail\nbatch=$1; stage=cloud.vk.com; stage_name=HTTP; verbose=1; started=$SECONDS\nprogress(){ printf "%s\\n" "$*" >&2; }; finish_progress(){ :; }\n'+helper+'\nfetch_http site "$2" > /dev/null\n'
 preflight=subprocess.run(['bash','-c',code,'test',directory,url],capture_output=True,text=True,timeout=9)
 (artifact/'cloud-vk-preflight.log').write_text(preflight.stderr)
 print('Production 1.5s preflight:', 'PASS' if preflight.returncode==0 else 'TIMEOUT/ERROR (see artifact)',flush=True)
 curl=subprocess.run(['curl','-sS','-L','--connect-timeout','5','--max-time','15','--max-redirs','50','--proto','=http,https','--proto-redir','=http,https','-o',str(root/'body'),'-D',str(root/'headers'),'-w','%{http_code}\t%{url_effective}\t%{num_redirects}\t%{time_total}\n',url],capture_output=True,text=True,timeout=18)
 curl_result={'returncode':curl.returncode,'meta':curl.stdout.strip(),'error':curl.stderr}
 (artifact/'cloud-vk-curl.json').write_text(json.dumps(curl_result,ensure_ascii=False,indent=2))
 print('Live curl 15s:',curl.stdout.strip(),curl.stderr.strip(),flush=True)
 # Run the browser even if curl fails, so artifacts show both observations.
 js=root/'open.cjs';js.write_text('''const fs=require('node:fs');
const {chromium}=require(process.env.SUBNET_PLAYWRIGHT);
(async()=>{const browser=await chromium.launch({headless:true});
try { const context=await browser.newContext({viewport:{width:1365,height:900},acceptDownloads:false});
 const page=await context.newPage();let last;
 page.on('response',r=>{if(r.request().isNavigationRequest() && r.frame()===page.mainFrame())last=r;});
 await page.goto('https://cloud.vk.com/',{waitUntil:'domcontentloaded',timeout:30000});
 await page.waitForTimeout(2000);
 const result={url:page.url(),status:last?.status(),title:await page.title(),htmlBytes:Buffer.byteLength(await page.content())};
 fs.writeFileSync(process.argv[2],JSON.stringify(result));
} finally { await browser.close(); }
})().catch(e=>{console.error(e.message);process.exitCode=1;});
''')
 runtime=os.environ.get('SUBNET_PLAYWRIGHT',str(pathlib.Path(os.environ.get('XDG_CACHE_HOME',str(pathlib.Path.home()/'.cache')))/'SubnetResolve/playwright-1.64.1/node_modules/playwright'))
 browser=subprocess.Popen(['node',str(js),str(artifact/'cloud-vk-browser.json')],env={**os.environ,'SUBNET_PLAYWRIGHT':runtime},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
 try:browser_out,browser_err=browser.communicate(timeout=40)
 except subprocess.TimeoutExpired:
  os.killpg(browser.pid,signal.SIGTERM)
  try:browser_out,browser_err=browser.communicate(timeout=3)
  except subprocess.TimeoutExpired:
   os.killpg(browser.pid,signal.SIGKILL);browser_out,browser_err=browser.communicate()
  browser_err+='\nBrowser test exceeded 40 seconds'
 (artifact/'cloud-vk-browser.log').write_text(browser_err)
 assert curl.returncode==0, curl_result
 status,final,count,elapsed=curl.stdout.strip().split('\t')
 assert status=='200' and urllib.parse.urlsplit(final).hostname=='cloud.vk.ru' and int(count)>=1,curl_result
 assert (root/'body').stat().st_size>0
 assert browser.returncode==0,browser_err
 data=json.loads((artifact/'cloud-vk-browser.json').read_text())
 assert 'vk cloud' in data['title'].lower(),data
 assert data['status']==200 and urllib.parse.urlsplit(data['url']).hostname=='cloud.vk.ru' and data['htmlBytes']>0,data
 if args.strict_preflight:assert preflight.returncode==0,preflight.stderr
 print('PASS live cloud.vk.com → cloud.vk.ru: curl + Chromium HTTP 200;',data['title'],flush=True)
