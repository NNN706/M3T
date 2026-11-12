const fs = require('node:fs');
const {activeMatchers, minimize} = require('./domain_coverage.cjs');
const jsonc = require('../../tests/xray/node_modules/jsonc-parser');

function parseTemplate(text) {
  const errors = [];
  const tree = jsonc.parseTree(text, errors, {allowTrailingComma: true});
  if (errors.length) throw Error('Шаблон routing-ru.json содержит некорректный JSONC');
  const rules = jsonc.findNodeAtLocation(tree, ['routing', 'rules']);
  if (!rules || rules.type !== 'array') throw Error('В шаблоне отсутствует routing.rules');
  return rules;
}

function fragments(data, field) {
  if (!data || !Array.isArray(data.rules)) throw Error('Отсутствует массив rules');
  const tags = new Set();
  return data.rules.map(rule => {
    if (typeof rule.ruleTag !== 'string' || !rule.ruleTag.trim() || tags.has(rule.ruleTag)) {
      throw Error('Некорректный или повторяющийся ruleTag');
    }
    tags.add(rule.ruleTag);
    if (!Array.isArray(rule[field]) || !rule[field].every(value => typeof value === 'string')) {
      throw Error('Некорректный массив ' + field);
    }
    return {ruleTag: rule.ruleTag, [field]: rule[field], outboundTag: 'direct'};
  }).filter(rule => rule[field].length > 0);
}

function compactDomains(template, domains) {
  const rules = parseTemplate(template).children?.map(node => jsonc.getNodeValue(node)) || [];
  return {rules: minimize(fragments(domains, 'domain'), activeMatchers(rules))
    .map(({outboundTag, ...rule}) => rule)};
}

function build(template, ips, domains) {
  const array = parseTemplate(template);
  const nodes = array.children || [];
  const values = nodes.map(node => jsonc.getNodeValue(node));
  const managed = values.map(rule => rule.outboundTag === 'direct' && Array.isArray(rule.ip)
    && Object.keys(rule).every(key => ['type', 'ruleTag', 'ip', 'outboundTag'].includes(key)));
  let insertion = managed.indexOf(true);
  if (insertion < 0) {
    // Keep generated rules before an existing catch-all routing rule.
    insertion = values.findIndex(rule => !rule.ip && !rule.domain && !rule.protocol
      && (rule.port || Object.keys(rule).every(key => ['outboundTag', 'ruleTag', 'type'].includes(key))));
    if (insertion < 0) insertion = nodes.length;
  }
  const ipRules = fragments(ips, 'ip');
  const domainRules = fragments(compactDomains(template, domains), 'domain');
  const render = value => JSON.stringify(value, null, 2).split('\n').map(line => '      ' + line).join('\n');
  const active = ipRules.map(render);
  const commented = domainRules.map(render).join(',\n').split('\n').map(line => '      // ' + line.slice(6));
  const generated = active.join(',\n');
  const domainBlock = domainRules.length ? commented.join('\n') : '';
  const pieces = [];
  for (let index = 0; index <= nodes.length; index++) {
    if (index === insertion) {
      if (generated || domainBlock) pieces.push({text: generated, tail: domainBlock, active: active.length > 0});
    }
    if (index < nodes.length && !managed[index]) {
      pieces.push({text: '      ' + template.slice(nodes[index].offset, nodes[index].offset + nodes[index].length), active: true});
    }
  }
  // Put separators between active objects, outside the commented domain block.
  let remaining = pieces.filter(piece => piece.active).length;
  const body = pieces.map(piece => {
    if (piece.active) remaining--;
    const suffix = piece.active && remaining > 0 ? ',' : '';
    return piece.text + suffix + (piece.tail ? '\n' + piece.tail : '') + '\n';
  }).join('');
  const result = template.slice(0, array.offset) + '[\n' + body + '    ]'
    + template.slice(array.offset + array.length);
  parseTemplate(result);
  return result;
}

if (require.main === module && process.argv[2] === '--compact-domains') {
  const [, templatePath, domainPath, sourcePath] = process.argv.slice(2);
  const cached = sourcePath ? JSON.parse(fs.readFileSync(sourcePath, 'utf8')).domain_observations : undefined;
  const result = compactDomains(fs.readFileSync(templatePath, 'utf8'), cached || JSON.parse(fs.readFileSync(domainPath, 'utf8')));
  fs.writeFileSync(domainPath + '.tmp', JSON.stringify(result, null, 2) + '\n');
  fs.renameSync(domainPath + '.tmp', domainPath);
} else if (require.main === module) {
  const [templatePath, ipPath, domainPath] = process.argv.slice(2);
  const result = build(fs.readFileSync(templatePath, 'utf8'),
    JSON.parse(fs.readFileSync(ipPath, 'utf8')), JSON.parse(fs.readFileSync(domainPath, 'utf8')));
  fs.writeFileSync(templatePath + '.tmp', result);
  fs.renameSync(templatePath + '.tmp', templatePath);
}
module.exports = {build, compactDomains};
