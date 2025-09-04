// server/sophos-collect.mjs
import axios from "axios";
import https from "https";
import { parseStringPromise } from "xml2js";
import FormData from "form-data";

const DEFAULT_TIPOS = [
  "FirewallRule", "NATRule", "Zone", "Interface", "VLAN", "DNS",
  "GatewayConfiguration", "UnicastRoute", "SDWANPolicyRoute", "VPNIPSecConnection",
  "DHCPServer", "XFRMInterface", "WebFilterPolicy", "WebFilterURLGroup",
  "ApplicationFilterPolicy", "AuthenticationServer", "SNMPCommunity",
  "BackupRestore", "AdminSettings", "User", "FQDNHost", "IPHost", "IPHostGroup",
  "MACHost", "Service", "ServiceGroup", "WebFilterURL"
];

const ts = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
};

async function fetchTipoXML(fw, tipo, ignoreTLS) {
  const reqxml = `
<Request>
  <Login><Username>${fw.username}</Username><Password>${fw.password}</Password></Login>
  <Get><${tipo}></${tipo}></Get>
</Request>`.trim();

  const form = new FormData();
  form.append("reqxml", reqxml);

  const httpsAgent = new https.Agent({ rejectUnauthorized: !ignoreTLS });
  const url = `https://${fw.ip}:${fw.port}/webconsole/APIController`;

  const res = await axios.post(url, form, {
    httpsAgent,
    headers: { ...form.getHeaders(), Accept: "application/xml" },
    timeout: 30000,
    maxBodyLength: Infinity,
  });
  return String(res.data ?? "");
}

function findNodesByTag(obj, tag, out = []) {
  if (!obj) return out;
  if (Array.isArray(obj)) return obj.forEach((x)=>findNodesByTag(x, tag, out)), out;
  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (k === tag) Array.isArray(v) ? out.push(...v) : out.push(v);
      findNodesByTag(v, tag, out);
    }
  }
  return out;
}

function flattenLeaves(node) {
  const out = {};
  const walk = (n, hint) => {
    if (n == null) return;
    if (["string","number","boolean"].includes(typeof n)) {
      const k = hint ?? "value";
      const val = String(n).trim();
      if (val) out[k] = out[k] ? `${out[k]},${val}` : val;
      return;
    }
    if (Array.isArray(n)) {
      if (n.length === 1) return walk(n[0], hint);
      if (n.every(x => ["string","number"].includes(typeof x))) {
        const k = hint ?? "value";
        const val = n.map(String).map(s=>s.trim()).filter(Boolean).join(",");
        if (val) out[k] = out[k] ? `${out[k]},${val}` : val;
        return;
      }
      return n.forEach(x=>walk(x, hint));
    }
    if (typeof n === "object") {
      for (const [k, v] of Object.entries(n)) {
        if (k === "$") continue;
        if (k === "_") { walk(v, hint); continue; }
        walk(v, k);
      }
    }
  };
  walk(node);
  return out;
}

async function parseGenerico(xml, tag) {
  if (!xml) return [];
  try {
    const j = await parseStringPromise(xml, { explicitArray: true, explicitRoot: true });
    const nodes = findNodesByTag(j, tag);
    return nodes.map(flattenLeaves);
  } catch {
    return [];
  }
}

function compararRegistros(atual, anterior, chave = "Name") {
  const id = (r, i) => r?.[chave] ?? `no_id_${i}`;
  const dA = new Map(atual.map((r,i)=>[id(r,i), r]));
  const dB = new Map(anterior.map((r,i)=>[id(r,i), r]));
  const novos = [], removidos = [], alterados = [];
  for (const [k, v] of dA) {
    if (!dB.has(k)) novos.push(v);
    else if (JSON.stringify(v) !== JSON.stringify(dB.get(k))) alterados.push({ id:k, antes:dB.get(k), depois:v });
  }
  for (const [k, v] of dB) if (!dA.has(k)) removidos.push(v);
  return { novos, removidos, alterados };
}

export async function sophosCollect(body) {
  const firewalls = Array.isArray(body.firewalls) ? body.firewalls : [];
  const tipos = (body.tipos?.length ? body.tipos : DEFAULT_TIPOS).slice();
  const ignoreTLS = !!body.ignoreTLS;
  const prevAll = body.previousSnapshot ?? null;

  if (!firewalls.length) throw new Error("firewalls vazio");

  const exec_timestamp = ts();
  const results = [];

  for (const fw of firewalls) {
    const dados = {};
    const diffs = {};
    for (const tipo of tipos) {
      try {
        const xml = await fetchTipoXML(fw, tipo, ignoreTLS);
        const blocos = await parseGenerico(xml, tipo);
        dados[tipo] = blocos;

        if (prevAll) {
          const prevFw = (prevAll.firewalls ?? []).find(x => x.ip === fw.ip || x.name === fw.name);
          const prevArr = prevFw?.dados?.[tipo] ?? [];
          diffs[tipo] = compararRegistros(blocos, prevArr, "Name");
        }
      } catch (e) {
        dados[tipo] = [];
        diffs[tipo] = { erro: String(e?.message ?? e) };
      }
    }
    results.push({ name: fw.name, ip: fw.ip, coletado_em: exec_timestamp, dados, diffs });
  }

  return { exec_timestamp, firewalls: results };
}
