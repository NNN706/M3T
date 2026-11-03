const fs = require('node:fs');
const ip = require('node:net');
const {parse} = require('jsonc-parser');
function prepare(text) {
  const errors = [];
  const config = parse(text, errors, {allowTrailingComma: true});
  if (errors.length || !config?.routing?.rules || !config.dns) throw Error('Некорректный JSONC шаблона');
  const outbounds = config.outbounds;
  if (!Array.isArray(outbounds)) throw Error('Нет outbounds');
  const direct = outbounds.find(o => o.tag === 'direct' && o.protocol === 'freedom');
  if (!direct) throw Error('Не найден freedom/direct');
  for (const rule of config.routing.rules) {
    if (rule.balancerTag) throw Error('Балансировщики в тестовом конфиге не поддерживаются');
    if (rule.outboundTag === 'proxy') rule.outboundTag = 'block';
    if (!['direct', 'block'].includes(rule.outboundTag)) throw Error('Неизвестный outboundTag');
  }
  config.outbounds = [{tag:'block', protocol:'blackhole', settings:{}}, direct];
  config.inbounds = [{tag:'routing-test-socks', listen:'0.0.0.0', port:10808,
    protocol:'socks', settings:{auth:'noauth', udp:false, userLevel:0},
    sniffing:{enabled:true, routeOnly:true, destOverride:['http','tls']}}];
  config.dns.tag = 'routing-test-internal-dns';
  config.routing.rules.unshift({type:'field', inboundTag:['routing-test-internal-dns'], outboundTag:'direct'});
  config.log = {...config.log, access:'/dev/stdout', error:'/dev/stderr', loglevel:'info'};
  // This literal IPv4 must fall through to the default block on TCP/443.
  // Reject unsupported IP matchers instead of assuming a negative probe is safe.
  const candidates = ['1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222'];
  const asInt = value => value.split('.').reduce((n,x) => n * 256 + Number(x), 0);
  const covered = address => config.routing.rules.some(rule => {
    if (rule.inboundTag && !rule.inboundTag.includes('routing-test-socks')) return false;
    if (rule.domain || rule.protocol) return false;
    if (rule.network && !rule.network.split(',').includes('tcp')) return false;
    if (rule.port && !String(rule.port).split(',').some(range => {
      const [a,b=a] = range.split('-').map(Number); return a <= 443 && b >= 443;
    })) return false;
    if (!rule.ip) return true;
    return rule.ip.some(cidr => {
      const [base, bits='32'] = cidr.split('/');
      if (ip.isIP(base) === 6) return false;
      if (ip.isIP(base) !== 4 || !/^\d+$/.test(bits) || +bits > 32) throw Error('Неподдерживаемый IP matcher: '+cidr);
      const size = 2 ** (32 - Number(bits));
      return Math.floor(asInt(base)/size) === Math.floor(asInt(address)/size);
    });
  });
  const negativeIP = candidates.find(a => !covered(a));
  if (!negativeIP) throw Error('Не найден адрес для проверки default block; проверьте правила');
  return {config, negativeIP};
}
if (require.main === module) {
  const result = prepare(fs.readFileSync(process.argv[2], 'utf8'));
  fs.mkdirSync(process.argv[3], {recursive:true});
  fs.writeFileSync(process.argv[3]+'/config.json', JSON.stringify(result.config,null,2)+'\n');
  fs.writeFileSync(process.argv[3]+'/negative-ip', result.negativeIP+'\n');
}
module.exports = {prepare};
