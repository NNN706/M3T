const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
test('remote Xray config validation failure preserves the working deployment',()=>{
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'xray-deploy-'));
  const bin=path.join(tmp,'bin'),home=path.join(tmp,'remote');fs.mkdirSync(bin);fs.mkdirSync(home);
  fs.writeFileSync(path.join(home,'working-config'),'previous configuration');
  fs.writeFileSync(path.join(bin,'ssh'),`#!/usr/bin/env python3
import os,sys,subprocess
args=sys.argv[1:]
while args and args[0].startswith('-'):
    args=args[2:]
args=args[1:]
if args and args[0]=='bash':
    command=args
else:
    command=['bash','-c',args[0]]
raise SystemExit(subprocess.call(command,cwd=os.environ['FAKE_REMOTE_HOME'],env={**os.environ,'HOME':os.environ['FAKE_REMOTE_HOME']}))
`,{mode:0o755});
  fs.writeFileSync(path.join(bin,'docker'),`#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_REMOTE_HOME/docker-commands"
if [[ $1 == pull ]]; then exit 0; fi
if [[ $1 == run ]]; then echo 'Invalid Xray config fixture' >&2; exit 1; fi
echo 'Unexpected mutation' >&2
exit 99
`,{mode:0o755});
  try {
    const result=spawnSync('bash',['deploy.sh'],{encoding:'utf8',env:{...process.env,PATH:bin+':'+process.env.PATH,
      FAKE_REMOTE_HOME:home,XRAY_HOST:'test.example',XRAY_USER:'tester',XRAY_IMAGE:'ghcr.io/xtls/xray-core:26.1.1@sha256:'+'a'.repeat(64),
      XRAY_SSH_KEY:'fixture-not-a-real-key',XRAY_KNOWN_HOSTS:'fixture',GITHUB_SHA:'b'.repeat(40),GITHUB_RUN_ID:'123',RUNNER_TEMP:tmp,
      XRAY_EVIDENCE:path.join(tmp,'evidence')},timeout:15000});
    assert.equal(result.status,1,result.stderr);
    assert.match(result.stderr,/Invalid Xray config fixture/);
    const commands=fs.readFileSync(path.join(home,'docker-commands'),'utf8');
    assert.match(commands,/run --rm --network none/);
    assert(!commands.includes('compose'));
    assert.equal(fs.readFileSync(path.join(home,'working-config'),'utf8'),'previous configuration');
  } finally {fs.rmSync(tmp,{recursive:true,force:true});}
});
