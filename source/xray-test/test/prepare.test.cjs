const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {prepare}=require('../prepare.cjs');
const base = ()=>({dns:{servers:['1.1.1.1']},routing:{domainStrategy:'IPOnDemand',rules:[
  {ip:['10.0.0.0/8'],outboundTag:'direct'}, {domain:['domain:example.com'],outboundTag:'proxy'}
]},outbounds:[{tag:'direct',protocol:'freedom'},{tag:'proxy',protocol:'vless',settings:{secret:'do not retain'}}]});
test('JSONC, default block, only direct/block, original order and DNS',()=>{
  const input=base();const {config,negativeIP}=prepare('// header\n'+JSON.stringify(input));
  assert.equal(config.outbounds[0].tag,'block');
  assert.equal(config.outbounds.length,2);
  assert.equal(config.routing.domainStrategy,'IPOnDemand');
  assert.deepEqual(config.routing.rules.slice(1),[input.routing.rules[0],{domain:['domain:example.com'],outboundTag:'block'}]);
  assert.deepEqual(config.dns.servers,input.dns.servers);
  assert.deepEqual(config.routing.rules[0].inboundTag,['routing-test-internal-dns']);
  assert.equal(config.inbounds[0].listen,'0.0.0.0');
  assert(!JSON.stringify(config).includes('do not retain'));
  assert.equal(negativeIP,'1.1.1.1');
});
test('reject invalid JSONC, unknown outbound and unsafe negative probe',()=>{
  assert.throws(()=>prepare('{no}'));
  let input=base();input.routing.rules[0].outboundTag='unknown';assert.throws(()=>prepare(JSON.stringify(input)));
  input=base();input.routing.rules=[{ip:['0.0.0.0/0'],outboundTag:'direct'}];assert.throws(()=>prepare(JSON.stringify(input)));
  input=base();input.routing.rules=[{ip:['geoip:ru'],outboundTag:'direct'}];assert.throws(()=>prepare(JSON.stringify(input)));
});
test('real repository template remains valid and unchanged',()=>{
  const text=fs.readFileSync('../../Templates/Routing-(RU-Direct)/routing-ru.json','utf8');
  const {config}=prepare(text);assert.equal(config.routing.domainStrategy,'IPOnDemand');
  assert.equal(config.outbounds[0].protocol,'blackhole');
  assert.equal(fs.readFileSync('../../Templates/Routing-(RU-Direct)/routing-ru.json','utf8'),text);
});
