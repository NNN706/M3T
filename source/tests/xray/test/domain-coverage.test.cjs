const test = require('node:test');
const assert = require('node:assert/strict');
const jsonc = require('jsonc-parser');
const {covers, activeMatchers, minimize} = require('../../../routing/scripts/domain_coverage.cjs');
const {build, compactDomains} = require('../../../routing/scripts/build_routing.cjs');

test('domain boundaries, exact full and literal keyword containment preserve matcher coverage', () => {
  assert(covers('domain:vtb.ru', 'domain:online.vtb.ru'));
  assert(covers('domain:vtb.ru', 'full:vtb.ru'));
  assert(!covers('domain:vtb.ru', 'domain:notvtb.ru'));
  assert(!covers('domain:vtb.ru', 'domain:vtb.ru.evil.example'));
  assert(!covers('full:vtb.ru', 'domain:vtb.ru'));
  assert(!covers('full:vtb.ru', 'full:online.vtb.ru'));
  assert(covers('keyword:yandex', 'domain:mc.yandex.ru'));
  assert(covers('keyword:yandex', 'keyword:mc.yandex'));
  assert(!covers('keyword:mc.yandex', 'keyword:yandex'));
  assert(!covers('domain:yandex.ru', 'keyword:yandex'));
  assert(!covers('keyword:', 'domain:vtb.ru'));
  assert(!covers('regexp:.*', 'domain:vtb.ru'));
  assert(!covers('keyword:YANDEX', 'domain:yandex.ru'));
});

test('only active unconditional direct rules count; other outbound/extra conditions never suppress output', () => {
  const rules = [
    {domain:['keyword:yandex'],outboundTag:'proxy'},
    {domain:['domain:vtb.ru'],port:'443',outboundTag:'direct'},
    {domain:['domain:vtb.ru'],ip:['192.0.2.0/24'],outboundTag:'direct'},
    {domain:['domain:vtb.ru'],inboundTag:['one'],outboundTag:'direct'},
    {domain:['keyword:sberbank'],outboundTag:'direct'},
  ];
  assert.deepEqual(activeMatchers(rules), ['keyword:sberbank']);
  const template = JSON.stringify({routing:{rules}});
  const input = {rules:[{ruleTag:'x',domain:['domain:online.vtb.ru','domain:mc.yandex.ru','domain:sberbank.ru']}]};
  assert.deepEqual(compactDomains(template,input), {rules:[{ruleTag:'x',domain:['domain:mc.yandex.ru','domain:online.vtb.ru']}]});
  const commentsOnly = '{"routing":{"rules":[/* {"domain":["keyword:yandex"],"outboundTag":"direct"} */]}}';
  assert.equal(compactDomains(commentsOnly,input).rules[0].domain.length, 3);
});

test('cross-group dedup removes empty groups, keeps owning tags and is deterministic/idempotent', () => {
  const input = [
    {ruleTag:'s2.vtb.ru', domain:['domain:s2.vtb.ru']},
    {ruleTag:'main', domain:['domain:vtb.ru','keyword:yandex']},
    {ruleTag:'other', domain:['domain:mc.yandex.ru','full:vtb.ru','domain:unrelated.example']},
    {ruleTag:'z', domain:['domain:unrelated.example','domain:unrelated.example']},
  ];
  const expected = [input[1], {ruleTag:'other', domain:['domain:unrelated.example']}];
  assert.deepEqual(minimize(input),expected);
  assert.deepEqual(minimize([...input].reverse()),expected);
  assert.deepEqual(minimize(expected),expected);
});

test('full active matcher cannot replace a generated suffix rule; coverage never broadens', () => {
  const rows = [{ruleTag:'x',domain:['domain:vtb.ru','full:online.vtb.ru','full:another.example']}];
  const reduced = minimize(rows,['full:vtb.ru']);
  assert.deepEqual(reduced,[{ruleTag:'x',domain:['domain:vtb.ru','full:another.example']}]);
  const template=JSON.stringify({routing:{rules:[{ruleTag:'main',domain:['domain:vtb.ru','keyword:yandex'],outboundTag:'direct'}]}});
  const domains={rules:[{ruleTag:'x',domain:['domain:online.vtb.ru','domain:mc.yandex.ru','domain:unrelated.example']}]};
  const built=build(template,{rules:[]},domains);
  assert(!built.includes('online.vtb.ru'));
  assert(!built.includes('mc.yandex.ru'));
  assert(built.includes('domain:unrelated.example'));
  assert.deepEqual(jsonc.parse(built).routing.rules,jsonc.parse(template).routing.rules);
  assert.equal(build(built,{rules:[]},domains),built);
});

test('published compact rules preserve observed root/subdomain coverage and introduce no new patterns', () => {
  const fs = require('node:fs'), path = require('node:path');
  const root = path.resolve(__dirname, '../../../..');
  const source = JSON.parse(fs.readFileSync(path.join(root, 'source/routing/state/sources.json')));
  const output = JSON.parse(fs.readFileSync(path.join(root, 'source/routing/generated/domains.json')));
  const template = jsonc.parse(fs.readFileSync(path.join(root, 'Templates/Routing-(RU-Direct)/routing-ru.json'),'utf8'));
  const original = source.domain_observations.rules.flatMap(rule => rule.domain);
  const compact = output.rules.flatMap(rule => rule.domain);
  const active = activeMatchers(template.routing.rules);
  assert(compact.every(value => original.includes(value)));
  assert(output.rules.every(rule => rule.domain.length > 0));
  const hostnames = new Set(original.flatMap(value => {
    const host = value.slice(value.indexOf(':')+1);
    return [host, 'probe.'+host, 'not'+host, host+'.outside.example'];
  }));
  const match = (value, host) => {
    const colon = value.indexOf(':'), kind = value.slice(0,colon), text = value.slice(colon+1);
    if (kind === 'full') return host === text;
    if (kind === 'domain') return host === text || host.endsWith('.'+text);
    return kind === 'keyword' && host.includes(text);
  };
  for (const host of hostnames) {
    assert.equal([...original,...active].some(value => match(value,host)),
      [...compact,...active].some(value => match(value,host)), host);
  }
});
