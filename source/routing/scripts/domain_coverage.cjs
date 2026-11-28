const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
// Conservative set containment for the supported Xray domain matcher types.
function matcher(value) {
  if (typeof value !== 'string' || value !== value.toLowerCase()) return null;
  const colon = value.indexOf(':');
  const kind = value.slice(0, colon), text = value.slice(colon + 1);
  if (colon < 0 || !text || !['full', 'domain', 'keyword'].includes(kind)) return null;
  return {kind, text};
}
function covers(broadValue, narrowValue) {
  const broad = matcher(broadValue), narrow = matcher(narrowValue);
  if (!broad || !narrow) return false;
  if (broad.kind === 'keyword') return narrow.text.includes(broad.text);
  if (narrow.kind === 'keyword') return false;
  if (broad.kind === 'full') return narrow.kind === 'full' && broad.text === narrow.text;
  return narrow.text === broad.text || narrow.text.endsWith('.' + broad.text);
}
function activeMatchers(rules) {
  return rules.filter(rule => rule.outboundTag === 'direct' && Array.isArray(rule.domain)
    && (!rule.type || rule.type === 'field')
    && Object.keys(rule).every(key => ['ruleTag', 'type', 'domain', 'outboundTag'].includes(key)))
    .flatMap(rule => rule.domain).filter(value => matcher(value));
}
function minimize(rules, active = []) {
  const candidates = rules.flatMap((rule, group) => rule.domain.map((value, index) => ({group, index, value})))
    .sort((a, b) => compare(rules[a.group].ruleTag, rules[b.group].ruleTag)
      || compare(a.value, b.value) || a.index - b.index);
  const kept = new Set();
  const parsed = new Map(candidates.map(row => [row, matcher(row.value)]));
  const activeValues = active.map(matcher).filter(Boolean);
  const activeKeywords = activeValues.filter(row => row.kind === 'keyword').map(row => row.text);
  const domains = new Set(activeValues.filter(row => row.kind === 'domain').map(row => row.text));
  const fulls = new Set(activeValues.filter(row => row.kind === 'full').map(row => row.text));
  const keywords = candidates.filter(row => parsed.get(row)?.kind === 'keyword');
  const minimalKeywords = keywords.filter((row, i) => !activeKeywords.some(text => parsed.get(row).text.includes(text))
    && !keywords.some((other, j) => j !== i && covers(other.value, row.value)
      && (!covers(row.value, other.value) || j < i)));
  for (const row of minimalKeywords) kept.add(row);
  const keywordTexts = [...activeKeywords, ...minimalKeywords.map(row => parsed.get(row).text)];
  const suffixCovered = text => {
    const labels = text.split('.');
    for (let i = 0; i < labels.length; i++) if (domains.has(labels.slice(i).join('.'))) return true;
    return false;
  };
  // Broad suffixes precede descendants, but equal matchers retain their original
  // deterministic owner. No pairwise comparison of hundreds of thousands of hosts.
  const ordered = candidates.filter(row => parsed.get(row)?.kind !== 'keyword').sort((a, b) => {
    const left = parsed.get(a), right = parsed.get(b);
    const rank = value => value?.kind === 'domain' ? 0 : value?.kind === 'full' ? 1 : 2;
    return rank(left) - rank(right)
      || (left?.kind === 'domain' ? left.text.split('.').length - right.text.split('.').length : 0);
  });
  for (const row of ordered) {
    const value = parsed.get(row);
    if (!value) { kept.add(row); continue; }
    if (keywordTexts.some(text => value.text.includes(text)) || suffixCovered(value.text)) continue;
    if (value.kind === 'full' && fulls.has(value.text)) continue;
    kept.add(row);
    (value.kind === 'domain' ? domains : fulls).add(value.text);
  }
  const grouped = new Map();
  for (const row of candidates) if (kept.has(row)) {
    if (!grouped.has(row.group)) grouped.set(row.group, new Set());
    grouped.get(row.group).add(row.value);
  }
  return rules.map((rule, group) => ({...rule, domain: [...(grouped.get(group) || [])].sort()}))
    .filter(rule => rule.domain.length).sort((a, b) => compare(a.ruleTag, b.ruleTag));
}
function readManual(text, label = 'domains.txt') {
  const rules = [], tags = new Set();
  let current;
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (line.startsWith('#### ')) {
      const ruleTag = line.slice(5).trim();
      if (!ruleTag || tags.has(ruleTag)) throw Error(`${label}:${index+1}: пустой или повторяющийся ruleTag`);
      tags.add(ruleTag); current = {ruleTag, domain: []}; rules.push(current);
      continue;
    }
    if (!line || line.startsWith('#')) continue;
    const value = line.split(/\s+#/, 1)[0].trim();
    if (!current) throw Error(`${label}:${index+1}: перед правилами нужен заголовок #### ruleTag`);
    if (!/^(full|domain|keyword):\S+$/.test(value)) throw Error(`${label}:${index+1}: ожидается full:, domain: или keyword: с непустым значением`);
    current.domain.push(value);
  }
  return {rules};
}
function respectExclusions(rules, excluded) {
  const blocked = new Set(excluded);
  return rules.map(rule => ({...rule, domain: rule.domain.flatMap(value => {
    const parsed = matcher(value);
    if (!parsed) return [value];
    if (!excluded.some(host => covers(value, 'full:' + host))) return [value];
    if (parsed.kind === 'domain' && !blocked.has(parsed.text)) return ['full:' + parsed.text];
    return [];
  })})).filter(rule => rule.domain.length);
}
module.exports = {covers, activeMatchers, minimize, readManual, respectExclusions};
