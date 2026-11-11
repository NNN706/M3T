const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const jsonc = require('jsonc-parser');
const {build} = require('../../routing/build_routing.cjs');

const ips = {rules: [{ruleTag: 'new.example', ip: ['192.0.2.0/24']}]};
const domains = {rules: [{ruleTag: 'new.example', domain: ['domain:new.example']}]};
const template = [
  '{',
  '  // DNS comment must survive.',
  '  "dns": {"servers": ["localhost"]},',
  '  "routing": {"rules": [',
  '    {"ip":["10.0.0.0/8"], "outboundTag":"block"},',
  '    {"protocol":["bittorrent"], "outboundTag":"direct"},',
  '    {"ruleTag":"old", "ip":["198.51.100.0/24"], "outboundTag":"direct"},',
  '    {"port":"443", "outboundTag":"direct"}',
  '  ]},',
  '  "inbounds": [],',
  '  "outbounds": [{"tag":"direct","protocol":"freedom"}]',
  '}',
].join('\n');

test('assembler replaces managed IPs, comments domains and preserves other config and rule order', () => {
  const built = build(template, ips, domains);
  const parsed = jsonc.parse(built);
  const old = jsonc.parse(template);
  assert.deepEqual(parsed.routing.rules, [
    old.routing.rules[0], old.routing.rules[1],
    {...ips.rules[0], outboundTag: 'direct'}, old.routing.rules[3],
  ]);
  assert.deepEqual(parsed.dns, old.dns);
  assert.deepEqual(parsed.inbounds, old.inbounds);
  assert.deepEqual(parsed.outbounds, old.outbounds);
  assert.match(built, /DNS comment must survive/);
  const commented = built.split('\n').filter(line => /^\s*\/\//.test(line))
    .map(line => line.replace(/^\s*\/\/\s?/, '')).join('\n');
  assert.match(commented, /"domain:new.example"/);
  assert.match(commented, /"outboundTag": "direct"/);
  assert.equal(build(built, ips, domains), built);
  const replaced = build(built, {rules: []}, {rules: []});
  assert.deepEqual(jsonc.parse(replaced).routing.rules, [
    old.routing.rules[0], old.routing.rules[1], old.routing.rules[3],
  ]);
  assert.equal(build(replaced, {rules: []}, {rules: []}), replaced);
});

test('assembler rejects invalid source and template before producing a config', () => {
  assert.throws(() => build('{', ips, domains), /JSONC/);
  assert.throws(() => build(template, {rules: [...ips.rules, ...ips.rules]}, domains), /ruleTag/);
  assert.throws(() => build(template, {rules: [{ruleTag: 'bad', ip: '192.0.2.0/24'}]}, domains));
  assert.equal(jsonc.parse(build(template, {rules: [{ruleTag: 'empty', ip: []}]}, domains))
    .routing.rules.length, 3);
});

test('real repository template embeds exactly the published IP fragments', () => {
  const root = path.resolve(__dirname, '../../..');
  const original = fs.readFileSync(path.join(root, 'Templates/Routing-(RU-Direct)/routing-ru.json'), 'utf8');
  const ip = JSON.parse(fs.readFileSync(path.join(root, 'source/routing/IP.json')));
  const domain = JSON.parse(fs.readFileSync(path.join(root, 'source/routing/domains.json')));
  const result = build(original, ip, domain);
  const config = jsonc.parse(result);
  assert.deepEqual(config.routing.rules.filter(rule => rule.outboundTag === 'direct' && rule.ip),
    ip.rules.filter(rule => rule.ip.length).map(rule => ({ruleTag: rule.ruleTag, ip: rule.ip, outboundTag: 'direct'})));
  assert.equal(result.split('BEGIN GENERATED DIRECT RULES').length, 2);
  assert.equal(result, build(result, ip, domain));
});
