const test=require('node:test');
const assert=require('node:assert/strict');
const {covers,minimize}=require('../../../routing/scripts/domain_coverage.cjs');
// Exhaustive reference from the previous implementation. Small randomized
// cases compare exact owners/order, while the large case exercises scalability.
function reference(rules,active=[]){
  const cmp=(a,b)=>a<b?-1:a>b?1:0;
  const rows=rules.flatMap((rule,group)=>rule.domain.map((value,index)=>({group,index,value})))
    .sort((a,b)=>cmp(rules[a.group].ruleTag,rules[b.group].ruleTag)||cmp(a.value,b.value)||a.index-b.index);
  const kept=new Set();
  for(let i=0;i<rows.length;i++){
    const current=rows[i];
    if(active.some(value=>covers(value,current.value)))continue;
    if(rows.some((other,j)=>j!==i&&covers(other.value,current.value)&&(!covers(current.value,other.value)||j<i)))continue;
    kept.add(current);
  }
  return rules.map((rule,group)=>({...rule,domain:[...new Set(rows.filter(r=>r.group===group&&kept.has(r)).map(r=>r.value))].sort()}))
    .filter(r=>r.domain.length).sort((a,b)=>cmp(a.ruleTag,b.ruleTag));
}
test('indexed minimization exactly matches exhaustive ownership and coverage',()=>{
  let seed=271128;const random=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
  const text=['example','foo.example','bar.foo.example','other.example','ample','foo','Upper.example'];
  const kinds=['domain:','full:','keyword:','regexp:'];
  for(let trial=0;trial<300;trial++){
    const rules=Array.from({length:5},(_,i)=>({ruleTag:`g${i}`,domain:Array.from({length:15},()=>kinds[random(kinds.length)]+text[random(text.length)])}));
    const active=Array.from({length:random(5)},()=>kinds[random(3)]+text[random(text.length)]);
    assert.deepEqual(minimize(rules,active),reference(rules,active));
  }
});
test('504000 domain groups collapse without quadratic comparisons',()=>{
  const rules=Array.from({length:504000},(_,i)=>({ruleTag:`g${i}`,domain:[`domain:h${i}.example`]}));
  rules.push({ruleTag:'root',domain:['domain:example']});
  assert.deepEqual(minimize(rules),[{ruleTag:'root',domain:['domain:example']}]);
});
