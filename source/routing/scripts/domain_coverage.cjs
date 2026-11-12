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
  for (let i = 0; i < candidates.length; i++) {
    const current = candidates[i];
    if (active.some(value => covers(value, current.value))) continue;
    if (candidates.some((other, j) => j !== i && covers(other.value, current.value)
      && (!covers(current.value, other.value) || j < i))) continue;
    kept.add(current);
  }
  return rules.map((rule, group) => ({...rule, domain: [...new Set(candidates
    .filter(row => row.group === group && kept.has(row)).map(row => row.value))].sort()}))
    .filter(rule => rule.domain.length).sort((a, b) => compare(a.ruleTag, b.ruleTag));
}
module.exports = {covers, activeMatchers, minimize};
