import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { toast } from "@/hooks/use-toast";
import {
  ChevronRight, ChevronDown, Shield, User as UserIcon, Shuffle, Boxes, Search,
  Globe, Settings, DatabaseBackup, KeyRound, Network, Users, TableProperties, ListFilter
} from "lucide-react";

// ===================== Tipos =====================
interface FirewallEntry {
  name?: string;
  ip?: string;
  coletado_em?: string;
  dados?: Record<string, any>;
}
interface FirewallJson {
  exec_timestamp?: string;
  firewalls?: FirewallEntry[];
  [key: string]: any;
}
interface Review {
  decision: "approved" | "rejected" | "";
  comment: string;
}
type ReviewMap = Record<string, Review>;

// ===================== Helpers genéricos =====================
const getArray = (maybe: any): any[] => {
  if (!maybe) return [];
  if (Array.isArray(maybe)) return maybe;
  if (typeof maybe === "object") return Object.values(maybe);
  return [];
};
const get = (obj: any, path: (string | number)[]) =>
  path.reduce((acc: any, k: any) => (acc && acc[k] !== undefined ? acc[k] : undefined), obj);
const toArray = (v: any) => (Array.isArray(v) ? v : v ? [v] : []);
const str = (v: any) => (v === undefined || v === null || v === "" ? "—" : String(v));
const sanitize = (s?: string) =>
  (s ?? "").toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9._-]/g, "");

const mask = (value: any) => {
  const raw = str(value);
  if (raw === "—") return raw;
  if (raw.length <= 6) return "••••";
  return raw.slice(0, 2) + "••••" + raw.slice(-2);
};

const joinLimited = (items: string[], limit = 2): string => {
  if (!items.length) return "—";
  if (items.length <= limit) return items.join(", ");
  return `${items.slice(0, limit).join(", ")}, +${items.length - limit}`;
};

const isTruthyYes = (v: any) => {
  const s = String(v ?? "").toLowerCase();
  return s === "1" || s === "enable" || s === "enabled" || s === "on" || s === "true" || s === "active";
};

const maskToCidr = (mask?: string) => {
  if (!mask) return null;
  const oct2bits: Record<number, number> = {
    255: 8, 254: 7, 252: 6, 248: 5, 240: 4, 224: 3, 192: 2, 128: 1, 0: 0,
  };
  const parts = mask.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || !(n in oct2bits))) return null;
  const bits = parts.reduce((acc, n) => acc + oct2bits[n], 0);
  return `/${bits}`;
};

const splitCommaList = (s?: string) =>
  (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : []);

// ===================== Helpers firewall & NAT =====================
const getRuleType = (rule: any, group: "FirewallRule" | "NATRule"): "Network" | "User" | "NAT" => {
  if (group === "NATRule") return "NAT";
  return (rule?.PolicyType as "Network" | "User") ?? "Network";
};
const getPolicyBlock = (rule: any, group: "FirewallRule" | "NATRule") => {
  if (group === "NATRule") return rule;
  const type = getRuleType(rule, group);
  return type === "User" ? rule?.UserPolicy ?? {} : rule?.NetworkPolicy ?? {};
};
const zonesToList = (value: any): string[] => {
  if (!value) return [];
  const z = typeof value === "string" ? value : value.Zone ?? value.zone;
  if (!z) return [];
  return toArray(z).map(String);
};
const networksToList = (value: any): string[] => {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
};
const servicesToList = (value: any): string[] => {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
};
const getRuleAction = (rule: any, group: "FirewallRule" | "NATRule") => {
  if (group === "FirewallRule") {
    return get(getPolicyBlock(rule, group), ["Action"]) ?? "—";
  }
  const tSrc = str(rule?.TranslatedSource ?? "Original");
  const tDst = str(rule?.TranslatedDestination ?? "Original");
  const tSvc = str(rule?.TranslatedService ?? "Original");
  return `src:${tSrc} · dst:${tDst} · svc:${tSvc}`;
};
const statusBadge = (status?: any) => {
  if (status === undefined || status === null || status === "") return <span>—</span>;
  const on = isTruthyYes(status) || String(status).toLowerCase() === "enable" || String(status).toLowerCase() === "enabled";
  return <Badge variant={on ? "default" : "secondary"}>{String(status)}</Badge>;
};
const TypeIcon: React.FC<{ type: "Network" | "User" | "NAT" }> = ({ type }) => {
  if (type === "User") return <UserIcon className="h-4 w-4" />;
  if (type === "NAT") return <Shuffle className="h-4 w-4" />;
  return <Shield className="h-4 w-4" />;
};

// chave estável evita perder foco do Textarea
const stableRuleKey = (rule: any, group: "FirewallRule" | "NATRule") => {
  const name = rule?.Name ?? rule?.name ?? "sem-nome";
  const ipf = rule?.IPFamily ?? rule?.ipFamily ?? "";
  const type = getRuleType(rule, group);
  const action = getRuleAction(rule, group);
  if (group === "FirewallRule") {
    const policy = getPolicyBlock(rule, group);
    const srcZ = zonesToList(get(policy, ["SourceZones"])).join(",");
    const dstZ = zonesToList(get(policy, ["DestinationZones"])).join(",");
    return `FW|${type}|${name}|${ipf}|${action}|${srcZ}|${dstZ}`;
  }
  // NAT incorpora campos originais/translated
  const oSrc = networksToList(get(rule, ["OriginalSourceNetworks", "Network"])).join(",");
  const oDst = networksToList(get(rule, ["OriginalDestinationNetworks", "Network"])).join(",");
  const oSvc = servicesToList(get(rule, ["OriginalServices", "Service"])).join(",");
  const tSrc = str(rule?.TranslatedSource);
  const tDst = str(rule?.TranslatedDestination);
  const tSvc = str(rule?.TranslatedService);
  return `NAT|${type}|${name}|${ipf}|${action}|${oSrc}|${oDst}|${oSvc}|${tSrc}|${tDst}|${tSvc}`;
};

// namespacing do localStorage
const makeStorageKey = (fw?: FirewallEntry | null, execTs?: string | null, what: string = "reviews") => {
  if (!fw) return null;
  const a = sanitize(fw.name);
  const b = sanitize(fw.ip);
  const c = sanitize(execTs ?? "");
  return `fa::${a}::${b}::${c}::${what}`;
};

// ===== Paginação & utilidades de tabela =====
function usePager<T>(items: T[], pageSize = 25) {
  const [page, setPage] = React.useState(1);
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const start = (page - 1) * pageSize;
  const pageData = items.slice(start, start + pageSize);
  React.useEffect(() => setPage(1), [items, pageSize]); // reset ao mudar dataset/filtro
  return { page, setPage, totalPages, pageData, start, pageSize };
}

const Pager: React.FC<{
  page: number; totalPages: number; setPage: (n: number)=>void;
  count: number; start: number; pageSize: number;
}> = ({ page, totalPages, setPage, count, start, pageSize }) => {
  const shown = Math.min(pageSize, Math.max(0, count - start));
  return (
    <div className="flex items-center justify-between px-2 py-2">
      <div className="text-xs text-muted-foreground">
        Mostrando {shown ? `${start + 1}–${start + shown}` : 0} de {count}
      </div>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={()=>setPage(Math.max(1, page-1))} disabled={page===1}>Anterior</Button>
        <Button variant="outline" size="sm" onClick={()=>setPage(Math.min(totalPages, page+1))} disabled={page===totalPages}>Próxima</Button>
      </div>
    </div>
  );
};

type Column = { key: string; header: string; monospace?: boolean; className?: string };

// ---------- Review Controls reutilizável ----------
const ReviewControls: React.FC<{
  rkey: string;
  reviews: ReviewMap;
  updateReview: (key: string, patch: Partial<Review>) => void;
  compact?: boolean;
}> = ({ rkey, reviews, updateReview, compact }) => {
  const r = reviews[rkey] ?? { decision: "", comment: "" };
  return (
    <div className="flex flex-col gap-2">
      <Select
        value={r.decision}
        onValueChange={(v) => updateReview(rkey, { decision: v as Review["decision"] })}
      >
        <SelectTrigger className="w-[160px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
        <SelectContent className="z-50">
          <SelectItem value="approved">Aprovar</SelectItem>
          <SelectItem value="rejected">Rejeitar</SelectItem>
        </SelectContent>
      </Select>
      <Textarea
        placeholder="Adicionar comentário"
        value={r.comment ?? ""}
        onChange={(e) => updateReview(rkey, { comment: e.currentTarget.value })}
        rows={compact ? 2 : 3}
        className="min-h-[36px]"
      />
    </div>
  );
};

const InventoryTable: React.FC<{
  title: string;
  rows: any[];
  columns: Column[];
  getRowKey?: (row: any, idx: number)=>string;
  expandable?: (row: any)=>React.ReactNode;
  pageSize?: number;
  // review embutido
  reviewKeyOfRow?: (row: any) => string | null;
  reviews?: ReviewMap;
  updateReview?: (key: string, patch: Partial<Review>) => void;
}> = ({ title, rows, columns, getRowKey, expandable, pageSize = 25, reviewKeyOfRow, reviews, updateReview }) => {
  const [open, setOpen] = React.useState<Record<string, boolean>>({});
  const { page, setPage, totalPages, pageData, start, pageSize: psize } = usePager(rows, pageSize);
  const extraCols = (expandable ? 1 : 0) + (reviewKeyOfRow ? 2 : 0);

  return (
    <div className="rounded-md border overflow-x-auto">
      <div className="px-3 py-2 text-sm font-medium">{title} ({rows.length})</div>
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((c) => <TableHead key={c.key} className={c.className}>{c.header}</TableHead>)}
            {expandable && <TableHead></TableHead>}
            {reviewKeyOfRow && (
              <>
                <TableHead>Decisão</TableHead>
                <TableHead>Comentário</TableHead>
              </>
            )}
          </TableRow>
        </TableHeader>
        <TableBody>
          {pageData.length ? pageData.map((row, i) => {
            const realIdx = start + i;
            const key = getRowKey ? getRowKey(row, realIdx) : `${title}-${sanitize(row?.name ?? row?.Name ?? "")}-${realIdx}`;
            const isOpen = !!open[key];
            const rkey = reviewKeyOfRow ? reviewKeyOfRow(row) : null;
            return (
              <React.Fragment key={key}>
                <TableRow>
                  {columns.map((c) => (
                    <TableCell key={c.key} className={c.monospace ? "font-mono" : undefined}>
                      {row[c.key] ?? "—"}
                    </TableCell>
                  ))}
                  {expandable && (
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" onClick={()=>setOpen(p=>({...p, [key]: !p[key]}))}>
                        {isOpen ? "Ocultar" : "Detalhes"}
                      </Button>
                    </TableCell>
                  )}
                  {reviewKeyOfRow && rkey && reviews && updateReview && (
                    <>
                      <TableCell className="align-top">
                        <Select
                          value={reviews[rkey]?.decision ?? ""}
                          onValueChange={(v) => updateReview(rkey, { decision: v as Review["decision"] })}
                        >
                          <SelectTrigger className="w-[140px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
                          <SelectContent className="z-50">
                            <SelectItem value="approved">Aprovar</SelectItem>
                            <SelectItem value="rejected">Rejeitar</SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell className="align-top">
                        <Textarea
                          placeholder="Adicionar comentário"
                          value={reviews[rkey]?.comment ?? ""}
                          onChange={(e) => updateReview(rkey, { comment: e.currentTarget.value })}
                          rows={2}
                          className="min-h-[36px]"
                        />
                      </TableCell>
                    </>
                  )}
                </TableRow>
                {expandable && isOpen && (
                  <TableRow className="bg-muted/30">
                    <TableCell colSpan={columns.length + extraCols}>
                      {expandable(row)}
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            );
          }) : (
            <TableRow><TableCell colSpan={columns.length + extraCols} className="text-sm text-muted-foreground">Nada encontrado.</TableCell></TableRow>
          )}
        </TableBody>
      </Table>
      <Pager page={page} setPage={setPage} totalPages={totalPages} count={rows.length} start={start} pageSize={psize} />
    </div>
  );
};

// ===================== Sessões =====================
// Admin
const SectionAdmin: React.FC<{ admin: any[]; makeRKey: (suffix: string)=>string; reviews: ReviewMap; updateReview: (k:string,p:Partial<Review>)=>void }> = ({ admin, makeRKey, reviews, updateReview }) => {
  const a = admin?.[0] ?? {};
  const hostname = get(a, ["HostnameSettings", "HostName"]);
  const wa = get(a, ["WebAdminSettings"]) ?? {};
  const rkey = makeRKey("admin:settings");
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><Settings className="h-4 w-4" /><h3 className="font-semibold">Admin</h3></div>
        <div className="flex gap-3">
          <ReviewControls rkey={rkey} reviews={reviews} updateReview={updateReview} compact />
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <div><div className="text-xs text-muted-foreground">Hostname</div><div className="text-sm">{str(hostname)}</div></div>
        <div><div className="text-xs text-muted-foreground">HTTPS Admin Port</div><div className="text-sm">{str(wa.HTTPSport)}</div></div>
        <div><div className="text-xs text-muted-foreground">User Portal Port</div><div className="text-sm">{str(wa.UserPortalHTTPSPort)}</div></div>
        <div><div className="text-xs text-muted-foreground">VPN Portal Port</div><div className="text-sm">{str(wa.VPNPortalHTTPSPort)}</div></div>
        <div><div className="text-xs text-muted-foreground">Portal Redirect Mode</div><div className="text-sm">{str(wa.PortalRedirectMode)}</div></div>
      </div>
    </Card>
  );
};

const SectionInventory: React.FC<{
  dados: any;
  makeRKey: (suffix: string)=>string;
  reviews: ReviewMap;
  updateReview: (k:string,p:Partial<Review>)=>void;
}> = ({ dados, makeRKey, reviews, updateReview }) => {
  const [q, setQ] = React.useState("");
  const ql = q.toLowerCase();

  // ===== fontes =====
  const ipHosts       = getArray(dados.IPHost);
  const ipHostGroups  = getArray(dados.IPHostGroup);
  const fqdnHosts     = getArray(dados.FQDNHost);
  const macHosts      = getArray(dados.MACHost);

  const services = [
    ...getArray(dados.Service),
    ...getArray(dados.Services),
  ];
  const serviceGroups = getArray(dados.ServiceGroup);

  // URL groups (compat + novo formato)
  const legacyURLGroups  = getArray(dados.URLGroup).map((g:any)=>({
    type: "URLGroup",
    name: g?.Name,
    description: g?.Description,
    isDefault: g?.IsDefault ?? "",
    urls: getArray(g?.URL) || getArray(get(g, ["URLList","URL"])) || []
  }));

  const webFilterURL     = getArray(dados.WebFilterURL)
                          .concat(getArray(dados.WebFilterUrl))
                          .map((u:any)=>({
                            type: "WebFilterURL",
                            name: u?.Name,
                            description: u?.Description,
                            isDefault: u?.IsDefault ?? "",
                            urls: [u?.URL ?? u?.Value ?? u?.Address].filter(Boolean)
                          }));

  const webFilterURLGroups = getArray(dados.WebFilterURLGroup).map((g:any)=>({
    type: "WebFilterURLGroup",
    name: g?.Name,
    description: g?.Description,
    isDefault: g?.IsDefault ?? "",
    urls: getArray(get(g, ["URLlist","URL"])) // <= seu formato
  }));

  const allUrlGroups = [...webFilterURLGroups, ...legacyURLGroups, ...webFilterURL];

  // ===== filtros utilitários =====
  const has = (v: any, needle: string) => String(v ?? "").toLowerCase().includes(needle);
  const anyIncludes = (arr: any[], needle: string) => arr.some((x)=>has(x, needle));

  // ===== IP Hosts (com HostType) =====
  const ipHostRows = ipHosts.map((o:any) => {
    const name = str(o?.Name);
    const hostType = String(o?.HostType ?? "").toLowerCase(); // iplist | iprange | network | ip | ""
    const ipFamily = str(o?.IPFamily);

    let value = "—";
    let count: number | string = "—";
    let details: any = null;

    if (hostType === "iplist") {
      const addrs = splitCommaList(o?.ListOfIPAddresses);
      value = joinLimited(addrs, 4);
      count = addrs.length;
      details = { kind: "list", addrs };
    } else if (hostType === "iprange") {
      const start = str(o?.StartIPAddress);
      const end = str(o?.EndIPAddress);
      value = `${start} – ${end}`;
      const groups = toArray(get(o, ["HostGroupList","HostGroup"])).map(String);
      details = { kind: "range", start, end, groups };
    } else if (hostType === "network") {
      const ip = str(o?.IPAddress);
      const mask = str(o?.Subnet);
      const cidr = maskToCidr(o?.Subnet);
      value = `${ip}${cidr ?? (mask !== "—" ? ` ${mask}` : "")}`;
      const groups = toArray(get(o, ["HostGroupList","HostGroup"])).map(String);
      details = { kind: "network", ip, mask, cidr, groups };
    } else if (hostType === "ip") {
      value = str(o?.IPAddress);
      details = { kind: "single", ip: value };
    } else {
      // fallback pra dumps antigos (IPAddress / Network)
      value = str(o?.IPAddress ?? o?.IP ?? o?.Network);
      details = { kind: "unknown", raw: value };
    }

    return { name, type: o?.HostType ?? "—", ipFamily, value, count, details };
  })
  .filter(r => !ql || has(r.name, ql) || has(r.type, ql) || has(r.value, ql));

  // ===== FQDN Hosts =====
  const fqdnRows = fqdnHosts
    .map((o:any)=>({ name: str(o?.Name), fqdn: str(o?.FQDN ?? o?.Hostname) }))
    .filter(r => !ql || has(r.name, ql) || has(r.fqdn, ql));

  // ===== IP Host Groups =====
  const ipHostGroupRows = ipHostGroups
    .map((o:any)=>{
      const members = getArray(get(o, ["Member", "Host"])) || getArray(o?.Members) || [];
      return { name: str(o?.Name), members, count: members.length };
    })
    .filter(r => !ql || has(r.name, ql) || anyIncludes(r.members, ql));

  // ===== MAC Hosts (Type: MACAddress | MACLIST) =====
  const macRows = macHosts.map((o:any) => {
    const name = str(o?.Name);
    const type = String(o?.Type ?? "").toLowerCase();

    let value = "—";
    let count: number | string = "—";
    let macs: string[] = [];

    if (type === "macaddress") {
      value = str(o?.MACAddress ?? o?.MAC);
      macs = [value].filter((v) => v !== "—");
      count = macs.length || "—";
    } else if (type === "maclist") {
      const raw = get(o, ["MACList","MACAddress"]);
      macs = (Array.isArray(raw) ? raw : raw ? [raw] : []).map(String);
      value = joinLimited(macs, 6);
      count = macs.length;
    } else {
      value = str(o?.MACAddress ?? o?.MAC);
      macs = value === "—" ? [] : [value];
      count = macs.length || "—";
    }

    return { name, type: o?.Type ?? "—", value, count, macs };
  })
  .filter(r => !ql || has(r.name, ql) || has(r.type, ql) || has(r.value, ql));

  // ===== Services =====
  const svcRows = services.map((s:any) => {
    const name = str(s?.Name);
    const type = str(s?.Type ?? s?.Protocol ?? "—");

    // Normaliza ServiceDetail -> array (objeto vira [objeto])
    const sd = get(s, ["ServiceDetails","ServiceDetail"]);
    const detailsArr = Array.isArray(sd) ? sd : (sd ? [sd] : []);

    // Tipo "IP" (ex.: AH) usa ProtocolName/ProtocolNumber
    if (type.toLowerCase() === "ip") {
      const ipd = detailsArr[0] ?? {};
      const protoName = str(ipd?.ProtocolName ?? s?.ProtocolName);
      const protoNum  = str(ipd?.ProtocolNumber ?? s?.ProtocolNumber);
      const summary   = protoName !== "—" ? `IP ${protoName}` : (protoNum !== "—" ? `IP ${protoNum}` : "IP");
      return {
        name, type, summary, count: protoName !== "—" || protoNum !== "—" ? 1 : "—",
        details: [], ipDetails: { ProtocolName: protoName, ProtocolNumber: protoNum },
      };
    }

    // TCP/UDP (ou similares)
    let details = detailsArr.map((d:any) => ({
      Protocol:       str(d?.Protocol ?? s?.Protocol ?? type),
      DestinationPort: str(d?.DestinationPort ?? s?.Port ?? s?.Ports),
      SourcePort:     str(d?.SourcePort ?? "—"),
    }));

    // Fallback antigo (quando não há ServiceDetails)
    if (!details.length && (s?.Protocol || s?.Port || s?.Ports)) {
      details = [{
        Protocol: str(s?.Protocol),
        DestinationPort: str(s?.Port ?? s?.Ports),
        SourcePort: "—",
      }];
    }

    const chips = details.map((d) => `${d.Protocol} ${d.DestinationPort}`);
    const summary = chips.length ? joinLimited(chips, 6) : "—";

    return { name, type, summary, count: details.length || "—", details };
  })
  .filter(r => !ql || [r.name, r.type, r.summary].some(v => String(v).toLowerCase().includes(ql)));

  // ===== Service Groups =====
  const svcGroupRows = serviceGroups
    .map((g:any)=>{
      const members = getArray(get(g, ["Member", "Service"])) || getArray(g?.Members) || [];
      return { name: str(g?.Name), members, count: members.length };
    })
    .filter(r => !ql || has(r.name, ql) || anyIncludes(r.members, ql));

  // ===== URL Groups =====
  const urlGroupRows = allUrlGroups
    .map((g:any)=>({
      type: g.type, name: str(g.name), isDefault: str(g.isDefault), description: str(g.description),
      urls: (g.urls || []).map(String), count: (g.urls || []).length
    }))
    .filter(r => !ql || has(r.name, ql) || has(r.description, ql) || anyIncludes(r.urls, ql));

  // ===== render =====
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-4">
        <Boxes className="h-4 w-4" />
        <h3 className="font-semibold">Inventário</h3>
      </div>

      {/* FIND global do inventário */}
      <div className="mb-4 flex items-center gap-2">
        <Search className="h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Buscar em objetos, serviços e URLs…"
          value={q}
          onChange={(e)=>setQ(e.target.value)}
          className="w-[360px]"
        />
        {!!q && <div className="text-xs text-muted-foreground">Filtrando por: “{q}”</div>}
      </div>

      <div className="grid gap-4">
        {/* IP Hosts */}
        <InventoryTable
          title="IP Hosts"
          rows={ipHostRows}
          columns={[
            { key: "name", header: "Nome" },
            { key: "type", header: "Tipo" },
            { key: "value", header: "Valor", monospace: true },
            { key: "count", header: "Itens (#)" },
          ]}
          getRowKey={(row) => `inv:iphost:${sanitize(row.name)}:${sanitize(row.value)}`}
          expandable={(row) => {
            if (row.details?.kind === "list") {
              return <div className="text-sm font-mono">{row.details.addrs.join(" • ")}</div>;
            }
            if (row.details?.kind === "range") {
              return (
                <div className="grid gap-2 md:grid-cols-3 text-sm">
                  <div><div className="text-xs text-muted-foreground">Início</div><div className="font-mono">{row.details.start}</div></div>
                  <div><div className="text-xs text-muted-foreground">Fim</div><div className="font-mono">{row.details.end}</div></div>
                  <div><div className="text-xs text-muted-foreground">HostGroups</div><div>{row.details.groups?.length ? joinLimited(row.details.groups, 10) : "—"}</div></div>
                </div>
              );
            }
            if (row.details?.kind === "network") {
              return (
                <div className="grid gap-2 md:grid-cols-3 text-sm">
                  <div><div className="text-xs text-muted-foreground">IP</div><div className="font-mono">{row.details.ip}</div></div>
                  <div><div className="text-xs text-muted-foreground">Subnet</div><div className="font-mono">{row.details.cidr ?? row.details.mask}</div></div>
                  <div><div className="text-xs text-muted-foreground">HostGroups</div><div>{row.details.groups?.length ? joinLimited(row.details.groups, 10) : "—"}</div></div>
                </div>
              );
            }
            return <div className="text-sm text-muted-foreground">Sem detalhes adicionais.</div>;
          }}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:iphost:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
          pageSize={25}
        />

        {/* FQDN Hosts */}
        <InventoryTable
          title="FQDN Hosts"
          rows={fqdnRows}
          columns={[
            { key: "name", header: "Nome" },
            { key: "fqdn", header: "FQDN", monospace: true },
          ]}
          getRowKey={(row)=>`inv:fqdn:${sanitize(row.name)}:${sanitize(row.fqdn)}`}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:fqdn:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
        />

        {/* IP Host Groups */}
        <InventoryTable
          title="IP Host Groups"
          rows={ipHostGroupRows}
          columns={[
            { key: "name", header: "Nome" },
            { key: "count", header: "Membros (#)" },
          ]}
          getRowKey={(row)=>`inv:iphostgroup:${sanitize(row.name)}`}
          expandable={(row) => (
            <div className="text-sm">{row.members?.length ? joinLimited(row.members.map(String), 30) : "—"}</div>
          )}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:iphostgroup:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
        />

        {/* MAC Hosts */}
        <InventoryTable
          title="MAC Hosts"
          rows={macRows}
          columns={[
            { key: "name", header: "Nome" },
            { key: "type", header: "Tipo" },
            { key: "value", header: "Valor(es)", monospace: true },
            { key: "count", header: "Itens (#)" },
          ]}
          getRowKey={(row)=>`inv:machost:${sanitize(row.name)}:${sanitize(row.value)}`}
          expandable={(row) => (
            <div className="text-sm font-mono">{row.macs?.length ? row.macs.join(" • ") : "—"}</div>
          )}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:machost:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
        />

        {/* Services */}
        <InventoryTable
          title="Services"
          rows={svcRows}
          columns={[
            { key: "name", header: "Nome" },
            { key: "type", header: "Tipo" },
            { key: "summary", header: "Definição", monospace: true },
            { key: "count", header: "Itens (#)" },
          ]}
          getRowKey={(row)=>`inv:service:${sanitize(row.name)}:${sanitize(row.type)}:${sanitize(row.summary)}`}
          expandable={(row) => (
            row.ipDetails ? (
              <div className="rounded-md border overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>ProtocolName</TableHead>
                      <TableHead>ProtocolNumber</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    <TableRow>
                      <TableCell className="font-mono">{row.ipDetails.ProtocolName}</TableCell>
                      <TableCell className="font-mono">{row.ipDetails.ProtocolNumber}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </div>
            ) : row.details?.length ? (
              <div className="rounded-md border overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Protocol</TableHead>
                      <TableHead>DestinationPort</TableHead>
                      <TableHead>SourcePort</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {row.details.map((d:any, i:number)=>(
                      <TableRow key={`svc-detail-${i}`}>
                        <TableCell className="font-mono">{d.Protocol}</TableCell>
                        <TableCell className="font-mono">{d.DestinationPort}</TableCell>
                        <TableCell className="font-mono">{d.SourcePort}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : <div className="text-sm text-muted-foreground">Sem detalhes.</div>
          )}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:service:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
        />

        {/* Service Groups */}
        <InventoryTable
          title="Service Groups"
          rows={svcGroupRows}
          columns={[
            { key: "name", header: "Nome" },
            { key: "count", header: "Membros (#)" },
          ]}
          getRowKey={(row)=>`inv:servicegroup:${sanitize(row.name)}`}
          expandable={(row) => (
            <div className="text-sm">{row.members?.length ? joinLimited(row.members.map(String), 30) : "—"}</div>
          )}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:servicegroup:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
        />

        {/* URL Groups (inclui WebFilterURLGroup + compat) */}
        <InventoryTable
          title="Web/URL Groups"
          rows={urlGroupRows}
          columns={[
            { key: "type", header: "Tipo" },
            { key: "name", header: "Nome" },
            { key: "count", header: "Itens (#)" },
            { key: "isDefault", header: "Default" },
          ]}
          getRowKey={(row)=>`inv:urlgroup:${sanitize(row.type)}:${sanitize(row.name)}`}
          expandable={(row) => <UrlsExpandable urls={row.urls} />}
          reviewKeyOfRow={(row)=> makeRKey(`inventory:urlgroup:${sanitize(row.name)}`)}
          reviews={reviews}
          updateReview={updateReview}
          pageSize={15}
        />
      </div>
    </Card>
  );
};

// Lista de URLs com paginação própria (para expand de URL Groups)
const UrlsExpandable: React.FC<{ urls: string[] }> = ({ urls }) => {
  const { page, setPage, totalPages, pageData, start, pageSize } = usePager(urls, 30);
  return (
    <div>
      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>#</TableHead>
              <TableHead>URL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pageData.length ? pageData.map((u, i) => (
              <TableRow key={`${u}-${start+i}`}>
                <TableCell className="w-[80px]">{start + i + 1}</TableCell>
                <TableCell className="font-mono">{u}</TableCell>
              </TableRow>
            )) : (
              <TableRow><TableCell colSpan={2} className="text-sm text-muted-foreground">Sem URLs.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <Pager page={page} setPage={setPage} totalPages={totalPages} count={urls.length} start={start} pageSize={pageSize} />
    </div>
  );
};

// Backup
const SectionBackup: React.FC<{ backup: any[]; makeRKey: (suffix: string)=>string; reviews: ReviewMap; updateReview: (k:string,p:Partial<Review>)=>void }> = ({ backup, makeRKey, reviews, updateReview }) => {
  const b = backup?.[0]?.ScheduleBackup ?? {};
  const rkey = makeRKey("backup:schedule");
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><DatabaseBackup className="h-4 w-4" /><h3 className="font-semibold">Backup</h3></div>
        <ReviewControls rkey={rkey} reviews={reviews} updateReview={updateReview} compact />
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <div><div className="text-xs text-muted-foreground">Modo</div><div className="text-sm">{str(b.BackupMode)}</div></div>
        <div><div className="text-xs text-muted-foreground">Servidor</div><div className="text-sm">{str(b.FTPServer)}</div></div>
        <div><div className="text-xs text-muted-foreground">Usuário</div><div className="text-sm">{str(b.Username)}</div></div>
        <div><div className="text-xs text-muted-foreground">Prefixo</div><div className="text-sm">{str(b.BackupPrefix)}</div></div>
        <div><div className="text-xs text-muted-foreground">Frequência</div><div className="text-sm">{str(b.BackupFrequency)}</div></div>
        <div><div className="text-xs text-muted-foreground">Dia/Hora</div><div className="text-sm">{[b.Day, b.Hour && `${b.Hour}:${b.Minute ?? "00"}`].filter(Boolean).join(" • ") || "—"}</div></div>
        <div><div className="text-xs text-muted-foreground">Caminho</div><div className="text-sm">{str(b.FtpPath)}</div></div>
        <div><div className="text-xs text-muted-foreground">Senha</div><div className="text-sm">{mask(b.Password)}</div></div>
        <div><div className="text-xs text-muted-foreground">Senha de Criptografia</div><div className="text-sm">{mask(b.EncryptionPassword)}</div></div>
      </div>
    </Card>
  );
};

// DNS
const SectionDNS: React.FC<{ dnsList: any[]; makeRKey: (suffix: string)=>string; reviews: ReviewMap; updateReview: (k:string,p:Partial<Review>)=>void }> = ({ dnsList, makeRKey, reviews, updateReview }) => {
  const obj = dnsList.find((x) => typeof x === "object") ?? {};
  const v4 = get(obj, ["IPv4Settings", "DNSIPList"]) ?? {};
  const mode = get(obj, ["IPv4Settings", "ObtainDNSFrom"]);
  const rkey = makeRKey("dns:ipv4");
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><Globe className="h-4 w-4" /><h3 className="font-semibold">DNS</h3></div>
        <ReviewControls rkey={rkey} reviews={reviews} updateReview={updateReview} compact />
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <div><div className="text-xs text-muted-foreground">Modo</div><div className="text-sm">{str(mode)}</div></div>
        <div><div className="text-xs text-muted-foreground">DNS 1</div><div className="text-sm">{str(v4.DNS1)}</div></div>
        <div><div className="text-xs text-muted-foreground">DNS 2</div><div className="text-sm">{str(v4.DNS2)}</div></div>
        <div><div className="text-xs text-muted-foreground">DNS 3</div><div className="text-sm">{str(v4.DNS3)}</div></div>
      </div>
    </Card>
  );
};

// SNMP
const SectionSNMP: React.FC<{ communities: any[]; makeRKey: (suffix: string)=>string; reviews: ReviewMap; updateReview: (k:string,p:Partial<Review>)=>void }> = ({ communities, makeRKey, reviews, updateReview }) => {
  const rkey = makeRKey("snmp:communities");
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><Network className="h-4 w-4" /><h3 className="font-semibold">SNMP Communities</h3></div>
        <ReviewControls rkey={rkey} reviews={reviews} updateReview={updateReview} compact />
      </div>
      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Community</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>v1</TableHead>
              <TableHead>v2c</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {communities.map((c, i) => (
              <TableRow key={i}>
                <TableCell className="font-mono">
                  {String(c?.Name || "").startsWith("$sfos$") ? mask(c?.Name) : str(c?.Name)}
                </TableCell>
                <TableCell>{str(c?.IPAddress)}</TableCell>
                <TableCell>{str(c?.Supportv1ProtocolVersion)}</TableCell>
                <TableCell>{str(c?.Supportv2cProtocolVersion)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
};

// Autenticação (AD)
const SectionAuth: React.FC<{ authList: any[]; makeRKey: (suffix: string)=>string; reviews: ReviewMap; updateReview: (k:string,p:Partial<Review>)=>void }> = ({ authList, makeRKey, reviews, updateReview }) => {
  const ad = authList?.[0]?.ActiveDirectory ?? [];
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2"><KeyRound className="h-4 w-4" /><h3 className="font-semibold">Autenticação (Active Directory)</h3></div>
        <ReviewControls rkey={makeRKey("auth:ad")} reviews={reviews} updateReview={updateReview} compact />
      </div>
      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nome</TableHead>
              <TableHead>Endereço</TableHead>
              <TableHead>Porta</TableHead>
              <TableHead>Domínio</TableHead>
              <TableHead>NetBIOS</TableHead>
              <TableHead>Usuário</TableHead>
              <TableHead>Base DN</TableHead>
              <TableHead>Decisão</TableHead>
              <TableHead>Comentário</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ad.map((s: any, idx: number) => {
              const rk = makeRKey(`auth:adserver:${sanitize(s?.ServerName ?? String(idx))}`);
              return (
                <TableRow key={idx}>
                  <TableCell>{str(s.ServerName)}</TableCell>
                  <TableCell>{str(s.ServerAddress)}</TableCell>
                  <TableCell>{str(s.Port)}</TableCell>
                  <TableCell>{str(s.DomainName)}</TableCell>
                  <TableCell>{str(s.NetBIOSDomain)}</TableCell>
                  <TableCell>{str(s.ADSUsername)}</TableCell>
                  <TableCell>{str(get(s, ["SearchQueries", "Query"]))}</TableCell>
                  <TableCell className="align-top">
                    <Select
                      value={reviews[rk]?.decision ?? ""}
                      onValueChange={(v) => updateReview(rk, { decision: v as Review["decision"] })}
                    >
                      <SelectTrigger className="w-[140px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
                      <SelectContent className="z-50">
                        <SelectItem value="approved">Aprovar</SelectItem>
                        <SelectItem value="rejected">Rejeitar</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell className="align-top">
                    <Textarea
                      placeholder="Comentário"
                      value={reviews[rk]?.comment ?? ""}
                      onChange={(e) => updateReview(rk, { comment: e.currentTarget.value })}
                      rows={2}
                    />
                  </TableCell>
                </TableRow>
            )})}
          </TableBody>
        </Table>
      </div>
      <div className="mt-2 text-xs text-muted-foreground">* Senhas e segredos não são exibidos.</div>
    </Card>
  );
};

// DHCP (melhorado + review por escopo)
const SectionDHCP: React.FC<{
  dhcps: any[];
  makeRKey: (suffix: string)=>string;
  reviews: ReviewMap;
  updateReview: (k:string,p:Partial<Review>)=>void;
}> = ({ dhcps, makeRKey, reviews, updateReview }) => {
  const [open, setOpen] = useState<Record<string, boolean>>({});

  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-3"><TableProperties className="h-4 w-4" /><h3 className="font-semibold">DHCP</h3></div>
      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Status</TableHead>
              <TableHead>Nome</TableHead>
              <TableHead>Interface</TableHead>
              <TableHead>Subnet Mask</TableHead>
              <TableHead>Gateway</TableHead>
              <TableHead>DNS 1</TableHead>
              <TableHead>DNS 2</TableHead>
              <TableHead>Lease (Default/Max)</TableHead>
              <TableHead>Decisão</TableHead>
              <TableHead>Comentário</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {dhcps.map((d, i) => {
              const key = `${d?.Name ?? "dhcp"}-${i}`;
              const ipLease = get(d, ["IPLease", "IP"]);
              const ranges = toArray(ipLease).map(String);
              const staticLeases = getArray(get(d, ["StaticLease", "Lease"]));
              const rk = makeRKey(`dhcp:${sanitize(d?.Name ?? String(i))}`);

              return (
                <React.Fragment key={key}>
                  <TableRow>
                    <TableCell>{statusBadge(d?.Status)}</TableCell>
                    <TableCell className="font-medium">{str(d?.Name)}</TableCell>
                    <TableCell>{str(d?.Interface)}</TableCell>
                    <TableCell>{str(d?.SubnetMask)}</TableCell>
                    <TableCell>{str(d?.Gateway)}</TableCell>
                    <TableCell>{str(d?.PrimaryDNSServer)}</TableCell>
                    <TableCell>{str(d?.SecondaryDNSServer)}</TableCell>
                    <TableCell>{[str(d?.DefaultLeaseTime), str(d?.MaxLeaseTime)].join(" / ")}</TableCell>
                    <TableCell className="align-top">
                      <Select
                        value={reviews[rk]?.decision ?? ""}
                        onValueChange={(v) => updateReview(rk, { decision: v as Review["decision"] })}
                      >
                        <SelectTrigger className="w-[140px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
                        <SelectContent className="z-50">
                          <SelectItem value="approved">Aprovar</SelectItem>
                          <SelectItem value="rejected">Rejeitar</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell className="align-top">
                      <Textarea
                        placeholder="Comentário"
                        value={reviews[rk]?.comment ?? ""}
                        onChange={(e) => updateReview(rk, { comment: e.currentTarget.value })}
                        rows={2}
                      />
                    </TableCell>
                    <TableCell>
                      <Button variant="outline" size="sm" onClick={() => setOpen((p) => ({ ...p, [key]: !p[key] }))}>
                        {open[key] ? "Ocultar" : "Detalhes"}
                      </Button>
                    </TableCell>
                  </TableRow>

                  {open[key] && (
                    <TableRow className="bg-muted/30">
                      <TableCell colSpan={11}>
                        <div className="grid gap-3 md:grid-cols-3">
                          <div><div className="text-xs text-muted-foreground">IPLease (faixas)</div><div className="text-sm font-mono">{ranges.length ? ranges.join(" • ") : "—"}</div></div>
                          <div><div className="text-xs text-muted-foreground">Domain</div><div className="text-sm">{str(d?.DomainName)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Detectar Conflito</div><div className="text-sm">{str(d?.ConflictDetection)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Relay</div><div className="text-sm">{str(d?.LeaseForRelay)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Use Appliance DNS</div><div className="text-sm">{str(d?.UseApplianceDNSSettings)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Use Interface IP as GW</div><div className="text-sm">{str(d?.UseInterfaceIPasGateway)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Primary WINS</div><div className="text-sm">{str(d?.PrimaryWINSServer)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Secondary WINS</div><div className="text-sm">{str(d?.SecondaryWINSServer)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Boot Server</div><div className="text-sm">{str(d?.BootServer)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Boot File</div><div className="text-sm">{str(d?.BootFile)}</div></div>
                        </div>

                        {/* Static Leases */}
                        <div className="mt-4">
                          <div className="flex items-center gap-2 mb-2"><ListFilter className="h-4 w-4" /><div className="font-medium">Static Leases ({staticLeases.length})</div></div>
                          <div className="rounded-md border overflow-x-auto">
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead>Hostname</TableHead>
                                  <TableHead>MAC</TableHead>
                                  <TableHead>IP</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {staticLeases.length ? staticLeases.map((s: any, idx: number) => (
                                  <TableRow key={`${key}-lease-${idx}`}>
                                    <TableCell className="font-mono">{str(s?.HostName)}</TableCell>
                                    <TableCell className="font-mono">{str(s?.MACAddress)}</TableCell>
                                    <TableCell className="font-mono">{str(s?.IPAddress)}</TableCell>
                                  </TableRow>
                                )) : (
                                  <TableRow><TableCell colSpan={3} className="text-sm text-muted-foreground">Sem reservas.</TableCell></TableRow>
                                )}
                              </TableBody>
                            </Table>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
};

// Usuários (apenas ativos + type=Administrator; colunas: Name, Username, Profile + review)
const SectionUsers: React.FC<{
  users: any[];
  makeRKey: (suffix: string)=>string;
  reviews: ReviewMap;
  updateReview: (k:string,p:Partial<Review>)=>void;
}> = ({ users, makeRKey, reviews, updateReview }) => {
  const [q, setQ] = useState("");

  const isAdministrator = (u: any) => {
    const t = String(u?.UserType ?? u?.Profile ?? "").toLowerCase();
    return t.includes("administrator") || t === "admin";
  };
  const isActive = (u: any) => isTruthyYes(u?.Status);

  const filtered = useMemo(() => {
    let out = users.filter((u) => isAdministrator(u) && isActive(u));
    if (q) {
      const needle = q.toLowerCase();
      out = out.filter(
        (u) =>
          String(u?.Username ?? "").toLowerCase().includes(needle) ||
          String(u?.Name ?? "").toLowerCase().includes(needle)
      );
    }
    return out;
  }, [users, q]);

  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-3"><Users className="h-4 w-4" /><h3 className="font-semibold">Usuários Administradores Ativos ({filtered.length})</h3></div>

      <div className="flex flex-wrap gap-2 mb-3">
        <Input placeholder="Buscar por Username ou Nome…" value={q} onChange={(e) => setQ(e.target.value)} className="w-64" />
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nome</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>Profile</TableHead>
              <TableHead>Decisão</TableHead>
              <TableHead>Comentário</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((u, i) => {
              const rk = makeRKey(`user:${sanitize(u?.Username ?? String(i))}`);
              return (
                <TableRow key={`${u?.Username ?? "user"}-${i}`}>
                  <TableCell>{str(u?.Name)}</TableCell>
                  <TableCell className="font-mono">{str(u?.Username)}</TableCell>
                  <TableCell>{str(u?.Profile ?? u?.UserType)}</TableCell>
                  <TableCell className="align-top">
                    <Select
                      value={reviews[rk]?.decision ?? ""}
                      onValueChange={(v) => updateReview(rk, { decision: v as Review["decision"] })}
                    >
                      <SelectTrigger className="w-[140px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
                      <SelectContent className="z-50">
                        <SelectItem value="approved">Aprovar</SelectItem>
                        <SelectItem value="rejected">Rejeitar</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell className="align-top">
                    <Textarea
                      placeholder="Comentário"
                      value={reviews[rk]?.comment ?? ""}
                      onChange={(e) => updateReview(rk, { comment: e.currentTarget.value })}
                      rows={2}
                    />
                  </TableCell>
                </TableRow>
            )})}
            {!filtered.length && (
              <TableRow><TableCell colSpan={5} className="text-sm text-muted-foreground">Nenhum usuário administrador ativo encontrado.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
};

// WebFilter (genérico para WebFilter/WebFilterPolicy) + review em item e regra
const SectionWebFilter: React.FC<{
  data: any;
  makeRKey: (suffix: string)=>string;
  reviews: ReviewMap;
  updateReview: (k:string,p:Partial<Review>)=>void;
}> = ({ data, makeRKey, reviews, updateReview }) => {
  const profiles = getArray(data.WebFilter).map((x) => ({ __type: "WebFilter", ...x }));
  const policies = getArray(data.WebFilterPolicy).map((x) => ({ __type: "WebFilterPolicy", ...x }));
  const items = [...profiles, ...policies];

  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [openRule, setOpenRule] = useState<Record<string, boolean>>({});

  const categoryEntries = (rule: any) => {
    const raw = get(rule, ["CategoryList", "Category"]);
    const arr = Array.isArray(raw) ? raw : raw ? [raw] : [];
    // Normaliza -> [{ID, type}]
    return arr
      .map((c: any) => ({ ID: c?.ID ?? c?.Id ?? c?.name ?? "", type: c?.type ?? c?.Type ?? "Unknown" }))
      .filter((c) => c.ID);
  };

  const usersFrom = (rule: any): string[] => {
    const u = get(rule, ["UserList", "User"]);
    if (!u) return [];
    return Array.isArray(u) ? u.map(String) : [String(u)];
  };

  if (!items.length) {
    return (
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-1"><ListFilter className="h-4 w-4" /><h3 className="font-semibold">WebFilter</h3></div>
        <div className="text-sm text-muted-foreground">Sem dados de WebFilter no JSON.</div>
      </Card>
    );
  }

  const TopFlags: React.FC<{ it: any }> = ({ it }) => (
    <div className="grid gap-2 md:grid-cols-3">
      <div><div className="text-xs text-muted-foreground">Default Action</div><div className="text-sm">{str(it.DefaultAction)}</div></div>
      <div><div className="text-xs text-muted-foreground">SafeSearch</div><div className="text-sm">{isTruthyYes(it.EnforceSafeSearch) ? "On" : "Off"}</div></div>
      <div><div className="text-xs text-muted-foreground">Image Licensing</div><div className="text-sm">{isTruthyYes(it.EnforceImageLicensing) ? "On" : "Off"}</div></div>
      <div><div className="text-xs text-muted-foreground">YouTube strict</div><div className="text-sm">{isTruthyYes(it.YoutubeFilterIsStrict) ? "On" : "Off"}</div></div>
      <div><div className="text-xs text-muted-foreground">YouTube enabled</div><div className="text-sm">{isTruthyYes(it.YoutubeFilterEnabled) ? "On" : "Off"}</div></div>
      <div><div className="text-xs text-muted-foreground">X-Forwarded-For</div><div className="text-sm">{isTruthyYes(it.XFFEnabled) ? "On" : "Off"}</div></div>
      <div><div className="text-xs text-muted-foreground">Quota (min)</div><div className="text-sm">{str(it.QuotaLimit)}</div></div>
      <div><div className="text-xs text-muted-foreground">Download size limit</div><div className="text-sm">{str(it.DownloadFileSizeRestriction)} {isTruthyYes(it.DownloadFileSizeRestrictionEnabled) ? "(enabled)" : ""}</div></div>
      <div><div className="text-xs text-muted-foreground">Office 365</div><div className="text-sm">{isTruthyYes(it.Office365Enabled) ? "On" : "Off"}</div></div>
    </div>
  );

  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-3"><ListFilter className="h-4 w-4" /><h3 className="font-semibold">WebFilter / Policies</h3></div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tipo</TableHead>
              <TableHead>Nome</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Ação padrão / Modo</TableHead>
              <TableHead>Regras (#)</TableHead>
              <TableHead>Decisão</TableHead>
              <TableHead>Comentário</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((it: any, idx: number) => {
              const key = `${it.__type}-${idx}-${str(it?.Name ?? it?.PolicyName)}`;
              const tipo = it.__type;
              const nome = str(it?.Name ?? it?.PolicyName ?? it?.ProfileName);
              const status = str(it?.Status ?? it?.Enabled);
              const modo = str(it?.DefaultAction ?? it?.Mode ?? it?.Action);
              const rules = getArray(get(it, ["RuleList", "Rule"]));
              const isOpen = !!open[key];
              const rkItem = makeRKey(`webfilter:item:${sanitize(tipo)}:${sanitize(nome)}`);

              return (
                <React.Fragment key={key}>
                  <TableRow>
                    <TableCell>{tipo}</TableCell>
                    <TableCell className="font-medium">{nome}</TableCell>
                    <TableCell>{statusBadge(status)}</TableCell>
                    <TableCell className="truncate">{modo}</TableCell>
                    <TableCell>{rules.length || "—"}</TableCell>
                    <TableCell className="align-top">
                      <Select
                        value={reviews[rkItem]?.decision ?? ""}
                        onValueChange={(v) => updateReview(rkItem, { decision: v as Review["decision"] })}
                      >
                        <SelectTrigger className="w-[140px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
                        <SelectContent className="z-50">
                          <SelectItem value="approved">Aprovar</SelectItem>
                          <SelectItem value="rejected">Rejeitar</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell className="align-top">
                      <Textarea
                        placeholder="Comentário"
                        value={reviews[rkItem]?.comment ?? ""}
                        onChange={(e) => updateReview(rkItem, { comment: e.currentTarget.value })}
                        rows={2}
                      />
                    </TableCell>
                    <TableCell>
                      <Button variant="outline" size="sm" onClick={() => setOpen((p) => ({ ...p, [key]: !p[key] }))}>
                        {isOpen ? "Ocultar" : "Detalhes"}
                      </Button>
                    </TableCell>
                  </TableRow>

                  {isOpen && (
                    <TableRow className="bg-muted/30">
                      <TableCell colSpan={8}>
                        {/* Cabeçalho com toggles/chaves da policy */}
                        {tipo === "WebFilterPolicy" && <div className="mb-4"><TopFlags it={it} /></div>}

                        {/* Lista de regras */}
                        {rules.length ? (
                          <div className="rounded-md border overflow-x-auto">
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead>#</TableHead>
                                  <TableHead>Users/Grupos</TableHead>
                                  <TableHead>Categorias (WebCategory / URLGroup)</TableHead>
                                  <TableHead>HTTP</TableHead>
                                  <TableHead>HTTPS</TableHead>
                                  <TableHead>Schedule</TableHead>
                                  <TableHead>Enabled</TableHead>
                                  <TableHead>Decisão</TableHead>
                                  <TableHead>Comentário</TableHead>
                                  <TableHead></TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {rules.map((r: any, rIdx: number) => {
                                  const rKey = `${key}-rule-${rIdx}`;
                                  const cats = categoryEntries(r);
                                  const wc = cats.filter((c) => c.type === "WebCategory");
                                  const ug = cats.filter((c) => c.type === "URLGroup");
                                  const users = usersFrom(r);
                                  const http = str(r.HTTPAction);
                                  const https = str(r.HTTPSAction);
                                  const sched = str(r.Schedule);
                                  const enabled = isTruthyYes(r.PolicyRuleEnabled);
                                  const follow = isTruthyYes(r.FollowHTTPAction);
                                  const isOpenR = !!openRule[rKey];
                                  const rkRule = makeRKey(`webfilter:rule:${sanitize(nome)}:${rIdx}`);

                                  return (
                                    <React.Fragment key={rKey}>
                                      <TableRow>
                                        <TableCell>{rIdx + 1}</TableCell>
                                        <TableCell className="truncate" title={users.join(", ") || "—"}>
                                          {users.length ? joinLimited(users, 4) : "—"}
                                        </TableCell>
                                        <TableCell className="truncate" title={`WebCategory:${wc.length} URLGroup:${ug.length}`}>
                                          {`WebCat:${wc.length} • URLGroup:${ug.length}`}
                                        </TableCell>
                                        <TableCell>{follow ? `${http} (follow)` : http}</TableCell>
                                        <TableCell>{https}</TableCell>
                                        <TableCell>{sched}</TableCell>
                                        <TableCell>{enabled ? "Yes" : "No"}</TableCell>
                                        <TableCell className="align-top">
                                          <Select
                                            value={reviews[rkRule]?.decision ?? ""}
                                            onValueChange={(v) => updateReview(rkRule, { decision: v as Review["decision"] })}
                                          >
                                            <SelectTrigger className="w-[120px]"><SelectValue placeholder="Selec." /></SelectTrigger>
                                            <SelectContent className="z-50">
                                              <SelectItem value="approved">Aprovar</SelectItem>
                                              <SelectItem value="rejected">Rejeitar</SelectItem>
                                            </SelectContent>
                                          </Select>
                                        </TableCell>
                                        <TableCell className="align-top">
                                          <Textarea
                                            placeholder="Comentário"
                                            value={reviews[rkRule]?.comment ?? ""}
                                            onChange={(e) => updateReview(rkRule, { comment: e.currentTarget.value })}
                                            rows={2}
                                          />
                                        </TableCell>
                                        <TableCell>
                                          <Button variant="outline" size="sm" onClick={() => setOpenRule((p) => ({ ...p, [rKey]: !p[rKey] }))}>
                                            {isOpenR ? "Ocultar" : "Ver categorias"}
                                          </Button>
                                        </TableCell>
                                      </TableRow>

                                      {isOpenR && (
                                        <TableRow className="bg-muted/40">
                                          <TableCell colSpan={10}>
                                            <div className="grid gap-3 md:grid-cols-2">
                                              <div>
                                                <div className="text-xs text-muted-foreground">WebCategories ({wc.length})</div>
                                                <div className="text-sm">{wc.length ? joinLimited(wc.map((x) => String(x.ID)), 20) : "—"}</div>
                                              </div>
                                              <div>
                                                <div className="text-xs text-muted-foreground">URLGroups ({ug.length})</div>
                                                <div className="text-sm">{ug.length ? joinLimited(ug.map((x) => String(x.ID)), 20) : "—"}</div>
                                              </div>
                                              <div className="md:col-span-2">
                                                <div className="text-xs text-muted-foreground">Exceptions / FileTypeCategory</div>
                                                <div className="text-sm">
                                                  {Object.keys(get(r, ["ExceptionList", "FileTypeCategory"]) ?? {}).length ? "Configured" : "—"}
                                                </div>
                                              </div>
                                            </div>
                                          </TableCell>
                                        </TableRow>
                                      )}
                                    </React.Fragment>
                                  );
                                })}
                              </TableBody>
                            </Table>
                          </div>
                        ) : (
                          <div className="text-sm text-muted-foreground">Sem regras (RuleList).</div>
                        )}
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
};

// ===================== Componente principal =====================
const FirewallAssessment: React.FC = () => {
  const [data, setData] = useState<FirewallJson | null>(null);
  const [fwIndex, setFwIndex] = useState<number>(0);
  const [reviews, setReviews] = useState<ReviewMap>({});
  const [tab, setTab] = useState<string>("firewall");
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // SEO básico
  useEffect(() => {
    document.title = "Assessment de Firewall | Análise de Regras";
    const description = "Faça upload do JSON de firewall, aprove/rejeite regras e adicione comentários.";
    let meta = document.querySelector('meta[name="description"]') as HTMLMetaElement | null;
    if (!meta) { meta = document.createElement("meta"); meta.name = "description"; document.head.appendChild(meta); }
    meta.content = description;
    let canonical = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
    if (!canonical) { canonical = document.createElement("link"); canonical.rel = "canonical"; document.head.appendChild(canonical); }
    canonical.href = window.location.href;
  }, []);

  const firewalls = data?.firewalls ?? [];
  const current = firewalls[fwIndex];

  const firewallRules = useMemo(() => getArray(get(current, ["dados", "FirewallRule"])), [current]);
  const natRules = useMemo(() => getArray(get(current, ["dados", "NATRule"])), [current]);

  // storage keys
  const storageKeyReviews = useMemo(() => makeStorageKey(current ?? null, data?.exec_timestamp ?? null, "reviews"), [current, data?.exec_timestamp]);
  const storageKeyTab = useMemo(() => makeStorageKey(current ?? null, data?.exec_timestamp ?? null, "tab"), [current, data?.exec_timestamp]);
  const storageKeyFwIndex = "fa::fwIndex";

  // Restaurar estado quando muda dataset/firewall
  useEffect(() => {
    if (storageKeyTab) {
      const t = localStorage.getItem(storageKeyTab);
      setTab(t || "firewall");
    }
    if (storageKeyReviews) {
      try {
        const raw = localStorage.getItem(storageKeyReviews);
        setReviews(raw ? JSON.parse(raw) : {});
      } catch { setReviews({}); }
    }
    setOpenRows({});
  }, [storageKeyTab, storageKeyReviews]);

  // Persistir reviews/aba
  useEffect(() => { if (storageKeyTab) localStorage.setItem(storageKeyTab, tab); }, [storageKeyTab, tab]);
  useEffect(() => { if (storageKeyReviews) try { localStorage.setItem(storageKeyReviews, JSON.stringify(reviews)); } catch {} }, [storageKeyReviews, reviews]);

  // Restaurar último firewall index usado (global)
  useEffect(() => {
    const raw = localStorage.getItem(storageKeyFwIndex);
    if (raw) setFwIndex(parseInt(raw, 10) || 0);
  }, []);
  useEffect(() => { localStorage.setItem(storageKeyFwIndex, String(fwIndex)); }, [fwIndex]);

  const handlePickFile = () => fileInputRef.current?.click();
  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const json = JSON.parse(text);
      setData(json);
      setFwIndex(0);
      const fw0 = json?.firewalls?.[0];
      toast({
        title: "Arquivo carregado",
        description: `Encontrados ${getArray(fw0?.dados?.FirewallRule).length} regras de firewall e ${getArray(fw0?.dados?.NATRule).length} regras NAT`,
      });
    } catch (err: any) {
      toast({ title: "JSON inválido", description: String(err?.message ?? err) });
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const updateReview = useCallback((key: string, patch: Partial<Review>) => {
    setReviews((prev) => ({
      ...prev,
      [key]: { decision: prev[key]?.decision ?? "", comment: prev[key]?.comment ?? "", ...patch },
    }));
  }, []);

  const exportReviews = () => {
    const now = new Date().toISOString();
    const payload = {
      generated_at: now,
      source_exec_timestamp: data?.exec_timestamp ?? null,
      firewall: current?.name ?? null,
      ip: current?.ip ?? null,
      totals: {
        firewallRules: firewallRules.length,
        natRules: natRules.length,
        reviewed: Object.keys(reviews).length,
      },
      reviews,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assessment-firewall-${sanitize(current?.name)}-${now}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast({ title: "Exportado com sucesso", description: "Arquivo JSON gerado." });
  };

  const clearAll = () => {
    setData(null);
    setReviews({});
    setOpenRows({});
    toast({ title: "Limpo", description: "Dados e avaliações foram limpos." });
  };

  // helper p/ gerar keys por seção
  const makeRKey = useCallback((suffix: string) => {
    const base = makeStorageKey(current ?? null, data?.exec_timestamp ?? null, "reviewitem") ?? "fa::global";
    return `${base}::${suffix}`;
  }, [current, data?.exec_timestamp]);

  // ---------- Header ----------
  const HeaderCard = (
    <Card className="p-4">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Assessment de Firewall</h1>
          <p className="text-muted-foreground">Envie o JSON exportado e avalie cada regra com decisão e comentários.</p>
        </div>
        <div className="flex gap-2">
          <Input ref={fileInputRef} type="file" accept="application/json,.json" className="hidden" onChange={handleFile} />
          <Button onClick={handlePickFile}>Upload JSON</Button>
          <Button variant="secondary" onClick={exportReviews} disabled={!data}>Exportar avaliação</Button>
          <Button variant="ghost" onClick={clearAll} disabled={!data}>Limpar</Button>
        </div>
      </header>

      {data && (
        <section className="mt-4 grid gap-3 md:grid-cols-4">
          <div>
            <span className="text-sm text-muted-foreground">Execução</span>
            <div className="text-sm">{data.exec_timestamp ?? "—"}</div>
          </div>
          <div>
            <span className="text-sm text-muted-foreground">Firewall</span>
            <div className="text-sm flex items-center gap-2">
              {firewalls.length > 1 ? (
                <Select value={String(fwIndex)} onValueChange={(v) => setFwIndex(parseInt(v, 10))}>
                  <SelectTrigger className="w-[280px]">
                    <SelectValue placeholder="Selecionar firewall" />
                  </SelectTrigger>
                  <SelectContent className="max-h-80">
                    {firewalls.map((f, i) => (
                      <SelectItem key={`${f.name}-${i}`} value={String(i)}>
                        {f?.name ?? `Firewall ${i + 1}`} • {f?.ip ?? "—"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <span>{current?.name ?? "—"}</span>
              )}
            </div>
          </div>
          <div>
            <span className="text-sm text-muted-foreground">IP</span>
            <div className="text-sm">{current?.ip ?? "—"}</div>
          </div>
          <div>
            <span className="text-sm text-muted-foreground">Coletado em</span>
            <div className="text-sm">{current?.coletado_em ?? "—"}</div>
          </div>
        </section>
      )}
    </Card>
  );

  // ---------- Tabelas de Regras ----------
  const RulesTable: React.FC<{ rules: any[]; group: "FirewallRule" | "NATRule" }> = ({ rules, group }) => {
    if (!data) return <div className="text-sm text-muted-foreground">Nenhum arquivo carregado ainda.</div>;
    if (!rules.length) return <div className="text-sm text-muted-foreground">Sem itens para exibir neste grupo.</div>;

    return (
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[10%]">Status</TableHead>
              <TableHead className="w-[10%]">Tipo</TableHead>
              <TableHead className="w-[22%]">Regra</TableHead>
              <TableHead className="w-[18%]">Ação</TableHead>
              <TableHead className="w-[12%]">{group === "NATRule" ? "—" : "Source Zone"}</TableHead>
              <TableHead className="w-[12%]">{group === "NATRule" ? "—" : "Destination Zone"}</TableHead>
              <TableHead className="w-[12%]">Decisão</TableHead>
              <TableHead>Comentário</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((rule) => {
              const name = rule?.Name ?? rule?.name ?? "sem-nome";
              const status = rule?.Status ?? rule?.status ?? "";
              const type = getRuleType(rule, group);
              const policy = getPolicyBlock(rule, group);
              const action = getRuleAction(rule, group);
              const srcZone = group === "NATRule" ? "—" : zonesToList(get(policy, ["SourceZones"])).join(", ");
              const dstZone = group === "NATRule" ? "—" : zonesToList(get(policy, ["DestinationZones"])).join(", ");
              const rowKey = stableRuleKey(rule, group);

              const review = reviews[rowKey] ?? { decision: "", comment: "" };
              const isOpen = !!openRows[rowKey];

              // extras (detalhes)
              const position = str(rule?.Position);
              const afterName = str(get(rule, ["After", "Name"]));

              // Firewall details
              const fwSrcNets = group === "FirewallRule"
                ? joinLimited(networksToList(get(policy, ["SourceNetworks", "Network"])), 6) : "—";
              const fwDstNets = group === "FirewallRule"
                ? joinLimited(networksToList(get(policy, ["DestinationNetworks", "Network"])), 6) : "—";
              const fwWebFilter = group === "FirewallRule" ? str(get(policy, ["WebFilter"])) : "—";
              const fwAppCtrl = group === "FirewallRule" ? str(get(policy, ["ApplicationControl"])) : "—";
              const fwIPS = group === "FirewallRule" ? str(get(policy, ["IntrusionPrevention"])) : "—";

              // NAT details
              const natOSrc = group === "NATRule" ? joinLimited(networksToList(get(rule, ["OriginalSourceNetworks", "Network"])), 6) : "—";
              const natODst = group === "NATRule" ? joinLimited(networksToList(get(rule, ["OriginalDestinationNetworks", "Network"])), 6) : "—";
              const natOSvc = group === "NATRule" ? joinLimited(servicesToList(get(rule, ["OriginalServices", "Service"])), 6) : "—";
              const natTSrc = group === "NATRule" ? str(rule?.TranslatedSource) : "—";
              const natTDst = group === "NATRule" ? str(rule?.TranslatedDestination) : "—";
              const natTSvc = group === "NATRule" ? str(rule?.TranslatedService) : "—";
              const natLinked = group === "NATRule" ? str(rule?.LinkedFirewallrule) : "—";
              const natMethod = group === "NATRule" ? str(rule?.NATMethod) : "—";
              const natOverride = group === "NATRule" ? str(rule?.OverrideInterfaceNATPolicy) : "—";
              const natHealth = group === "NATRule" ? str(rule?.HealthCheck) : "—";

              return (
                <React.Fragment key={rowKey}>
                  <TableRow>
                    <TableCell>{statusBadge(status)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <TypeIcon type={type} />
                        <span className="text-sm">{type}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <button
                        type="button"
                        className="inline-flex items-center gap-2 hover:opacity-80"
                        onClick={() => setOpenRows((prev) => ({ ...prev, [rowKey]: !prev[rowKey] }))}
                        aria-expanded={isOpen}
                        aria-controls={`details-${rowKey}`}
                      >
                        {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                        <span className="font-medium">{name}</span>
                      </button>
                    </TableCell>
                    <TableCell className="truncate" title={String(action)}>{String(action)}</TableCell>
                    <TableCell>{srcZone}</TableCell>
                    <TableCell>{dstZone}</TableCell>
                    <TableCell>
                      <Select
                        value={review.decision}
                        onValueChange={(v) => updateReview(rowKey, { decision: v as Review["decision"] })}
                      >
                        <SelectTrigger className="w-[160px]"><SelectValue placeholder="Selecionar" /></SelectTrigger>
                        <SelectContent className="z-50">
                          <SelectItem value="approved">Aprovar</SelectItem>
                          <SelectItem value="rejected">Rejeitar</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell>
                      <Textarea
                        placeholder="Adicionar comentário"
                        value={review.comment ?? ""}
                        onChange={(e) => updateReview(rowKey, { comment: e.currentTarget.value })}
                        className="min-h-[36px]"
                      />
                    </TableCell>
                  </TableRow>

                  {isOpen && (
                    <TableRow id={`details-${rowKey}`} className="bg-muted/30">
                      <TableCell colSpan={8}>
                        <div className="grid gap-3 md:grid-cols-3">
                          <div><div className="text-xs text-muted-foreground">IP Family</div><div className="text-sm">{str(rule?.IPFamily)}</div></div>
                          <div><div className="text-xs text-muted-foreground">Position</div><div className="text-sm">{position === "After" && afterName !== "—" ? `After "${afterName}"` : position}</div></div>
                          {group === "FirewallRule" ? (
                            <>
                              <div><div className="text-xs text-muted-foreground">Source Networks</div><div className="text-sm">{fwSrcNets}</div></div>
                              <div><div className="text-xs text-muted-foreground">Destination Networks</div><div className="text-sm">{fwDstNets}</div></div>
                              <div><div className="text-xs text-muted-foreground">WebFilter</div><div className="text-sm">{fwWebFilter}</div></div>
                              <div><div className="text-xs text-muted-foreground">Application Control</div><div className="text-sm">{fwAppCtrl}</div></div>
                              <div><div className="text-xs text-muted-foreground">Intrusion Prevention</div><div className="text-sm">{fwIPS}</div></div>
                            </>
                          ) : (
                            <>
                              <div><div className="text-xs text-muted-foreground">Original Source Networks</div><div className="text-sm font-mono">{natOSrc}</div></div>
                              <div><div className="text-xs text-muted-foreground">Original Destination Networks</div><div className="text-sm font-mono">{natODst}</div></div>
                              <div><div className="text-xs text-muted-foreground">Original Services</div><div className="text-sm font-mono">{natOSvc}</div></div>
                              <div><div className="text-xs text-muted-foreground">Translated Source</div><div className="text-sm">{natTSrc}</div></div>
                              <div><div className="text-xs text-muted-foreground">Translated Destination</div><div className="text-sm">{natTDst}</div></div>
                              <div><div className="text-xs text-muted-foreground">Translated Service</div><div className="text-sm">{natTSvc}</div></div>
                              <div><div className="text-xs text-muted-foreground">Linked Firewall Rule</div><div className="text-sm">{natLinked}</div></div>
                              <div><div className="text-xs text-muted-foreground">NAT Method</div><div className="text-sm">{natMethod}</div></div>
                              <div><div className="text-xs text-muted-foreground">Override Interface NAT Policy</div><div className="text-sm">{natOverride}</div></div>
                              <div><div className="text-xs text-muted-foreground">Health Check</div><div className="text-sm">{natHealth}</div></div>
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>
    );
  };

  // ---------- Render ----------
  const dados = current?.dados ?? {};
  return (
    <div className="container mx-auto max-w-7xl space-y-6 p-4">
      {HeaderCard}

      <main>
        <Tabs value={tab} onValueChange={setTab} className="space-y-4">
          <TabsList className="flex flex-wrap">
            <TabsTrigger value="firewall">Firewall Rules ({firewallRules.length})</TabsTrigger>
            <TabsTrigger value="nat">NAT Rules ({natRules.length})</TabsTrigger>
            <TabsTrigger value="admin">Admin</TabsTrigger>
            <TabsTrigger value="backup">Backup</TabsTrigger>
            <TabsTrigger value="dns">DNS</TabsTrigger>
            <TabsTrigger value="snmp">SNMP</TabsTrigger>
            <TabsTrigger value="auth">Autenticação</TabsTrigger>
            <TabsTrigger value="dhcp">DHCP</TabsTrigger>
            <TabsTrigger value="webfilter">WebFilter</TabsTrigger>
            <TabsTrigger value="users">Usuários</TabsTrigger>
            <TabsTrigger value="inventory">Inventário</TabsTrigger>
          </TabsList>

          <TabsContent value="firewall" className="space-y-4">
            <RulesTable rules={firewallRules} group="FirewallRule" />
          </TabsContent>

          <TabsContent value="nat" className="space-y-4">
            <RulesTable rules={natRules} group="NATRule" />
          </TabsContent>

          <TabsContent value="admin" className="space-y-4">
            <SectionAdmin admin={getArray(dados.AdminSettings)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="backup" className="space-y-4">
            <SectionBackup backup={getArray(dados.BackupRestore)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="dns" className="space-y-4">
            <SectionDNS dnsList={getArray(dados.DNS)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="snmp" className="space-y-4">
            <SectionSNMP communities={getArray(dados.SNMPCommunity)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="auth" className="space-y-4">
            <SectionAuth authList={getArray(dados.AuthenticationServer)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="dhcp" className="space-y-4">
            <SectionDHCP dhcps={getArray(dados.DHCPServer)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="webfilter" className="space-y-4">
            <SectionWebFilter data={dados} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="users" className="space-y-4">
            <SectionUsers users={getArray(dados.User)} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

          <TabsContent value="inventory" className="space-y-4">
            <SectionInventory dados={dados} makeRKey={makeRKey} reviews={reviews} updateReview={updateReview} />
          </TabsContent>

        </Tabs>
      </main>
    </div>
  );
};

export default FirewallAssessment;
