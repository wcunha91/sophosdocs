// src/pages/Collector.tsx
import React from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/hooks/use-toast";
import { Download, Play, Shield } from "lucide-react";

const DEFAULT_TIPOS = [
  "FirewallRule","NATRule","Zone","Interface","VLAN","DNS",
  "GatewayConfiguration","UnicastRoute","SDWANPolicyRoute","VPNIPSecConnection",
  "DHCPServer","XFRMInterface","WebFilterPolicy","WebFilterURLGroup",
  "ApplicationFilterPolicy","AuthenticationServer","SNMPCommunity",
  "BackupRestore","AdminSettings","User","FQDNHost","IPHost","IPHostGroup",
  "MACHost","Service","ServiceGroup","WebFilterURL"
];

type FormState = {
  name: string; ip: string; port: string;
  username: string; password: string;
  ignoreTLS: boolean;
  tipos: Record<string, boolean>;
  prevJson: string;
};

const saveAs = (filename: string, data: any) => {
  const blob = new Blob([typeof data === "string" ? data : JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
};

export default function Collector() {
  const [form, setForm] = React.useState<FormState>(() => {
    const last = typeof window !== "undefined" ? JSON.parse(localStorage.getItem("collector:last") || "null") : null;
    return {
      name: last?.name ?? "", ip: last?.ip ?? "", port: last?.port ?? "4444",
      username: last?.username ?? "", password: "",
      ignoreTLS: last?.ignoreTLS ?? true,
      tipos: Object.fromEntries(DEFAULT_TIPOS.map(t => [t, true])),
      prevJson: "",
    };
  });
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<any | null>(null);

  const selectedTipos = React.useMemo(
    () => Object.entries(form.tipos).filter(([,v])=>v).map(([k])=>k),
    [form.tipos]
  );

  const submit = async () => {
    if (!form.name || !form.ip || !form.port || !form.username || !form.password) {
      toast({ title: "Campos obrigatórios", description: "Preencha nome, IP, porta, usuário e senha." });
      return;
    }
    setLoading(true);
    try {
      localStorage.setItem("collector:last", JSON.stringify({
        name: form.name, ip: form.ip, port: form.port, username: form.username, ignoreTLS: form.ignoreTLS,
      }));

      const body = {
        firewalls: [{ name: form.name, ip: form.ip, port: Number(form.port), username: form.username, password: form.password }],
        tipos: selectedTipos.length ? selectedTipos : DEFAULT_TIPOS,
        ignoreTLS: form.ignoreTLS,
        previousSnapshot: form.prevJson ? JSON.parse(form.prevJson) : undefined,
      };

      const res = await fetch("/api/sophos-collect", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.json().catch(()=>({})))?.error || `HTTP ${res.status}`);
      const json = await res.json();
      setResult(json);
      toast({ title: "Coleta concluída", description: `Execução ${json.exec_timestamp}` });
    } catch (e:any) {
      toast({ title: "Falha na coleta", description: String(e?.message ?? e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto max-w-6xl p-4 space-y-6">
      <Card className="p-4 space-y-4">
        <div className="flex items-center gap-2"><Shield className="w-4 h-4" /><h1 className="text-lg font-semibold">Coletor Sophos (Node)</h1></div>
        <div className="grid gap-3 md:grid-cols-3">
          <div><Label>Nome</Label><Input value={form.name} onChange={e=>setForm(p=>({...p, name: e.target.value}))} placeholder="Firewall HSLG" /></div>
          <div><Label>IP/Host</Label><Input value={form.ip} onChange={e=>setForm(p=>({...p, ip: e.target.value}))} placeholder="10.0.0.1" /></div>
          <div><Label>Porta</Label><Input value={form.port} onChange={e=>setForm(p=>({...p, port: e.target.value}))} placeholder="4444" /></div>
          <div><Label>Usuário</Label><Input value={form.username} onChange={e=>setForm(p=>({...p, username: e.target.value}))} placeholder="admin" /></div>
          <div><Label>Senha</Label><Input type="password" value={form.password} onChange={e=>setForm(p=>({...p, password: e.target.value}))} placeholder="••••••" /></div>
          <div className="flex items-center gap-2 pt-6">
            <Checkbox id="ignoreTLS" checked={form.ignoreTLS} onCheckedChange={(v)=>setForm(p=>({...p, ignoreTLS: !!v}))} />
            <Label htmlFor="ignoreTLS">Ignorar verificação TLS (self-signed)</Label>
          </div>
        </div>

        <div>
          <Label className="mb-2 block">Tipos a coletar</Label>
          <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-y-2">
            {DEFAULT_TIPOS.map((t)=>(
              <label key={t} className="inline-flex items-center gap-2">
                <Checkbox checked={!!form.tipos[t]} onCheckedChange={(v)=>setForm(p=>({...p, tipos: {...p.tipos, [t]: !!v}}))}/>
                <span className="text-sm">{t}</span>
              </label>
            ))}
          </div>
          <div className="mt-2 flex gap-2">
            <Button variant="outline" size="sm" onClick={()=>setForm(p=>({...p, tipos: Object.fromEntries(DEFAULT_TIPOS.map(t=>[t,true]))}))}>Selecionar tudo</Button>
            <Button variant="outline" size="sm" onClick={()=>setForm(p=>({...p, tipos: Object.fromEntries(DEFAULT_TIPOS.map(t=>[t,false]))}))}>Limpar</Button>
          </div>
        </div>

        <div className="grid gap-2">
          <Label>Snapshot anterior (opcional, para diff)</Label>
          <Textarea rows={4} placeholder='Cole aqui o JSON anterior ({"exec_timestamp": "...", "firewalls":[...]})' value={form.prevJson} onChange={e=>setForm(p=>({...p, prevJson: e.target.value}))}/>
        </div>

        <div className="flex gap-2">
          <Button onClick={submit} disabled={loading}><Play className="w-4 h-4 mr-2" />{loading ? "Coletando..." : "Coletar"}</Button>
          {result && (
            <Button variant="secondary" onClick={()=>saveAs(`sophos-collect-${result.exec_timestamp}.json`, result)}>
              <Download className="w-4 h-4 mr-2" /> Baixar JSON
            </Button>
          )}
        </div>
      </Card>

      {result && (
        <Card className="p-4 space-y-3">
          <div className="text-sm text-muted-foreground">Execução: {result.exec_timestamp}</div>
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Firewall</TableHead><TableHead>IP</TableHead>
                  <TableHead>Tipo</TableHead><TableHead>Itens</TableHead>
                  <TableHead>Novos</TableHead><TableHead>Removidos</TableHead><TableHead>Alterados</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.firewalls.map((f: any, idx: number) => {
                  const tipos = Object.keys(f.dados ?? {});
                  return tipos.length ? tipos.map((t:string, i:number)=>(
                    <TableRow key={`${idx}-${t}`}>
                      <TableCell>{i===0 ? f.name : ""}</TableCell>
                      <TableCell>{i===0 ? f.ip : ""}</TableCell>
                      <TableCell>{t}</TableCell>
                      <TableCell>{Array.isArray(f.dados[t]) ? f.dados[t].length : 0}</TableCell>
                      <TableCell>{f.diffs?.[t]?.novos?.length ?? 0}</TableCell>
                      <TableCell>{f.diffs?.[t]?.removidos?.length ?? 0}</TableCell>
                      <TableCell>{f.diffs?.[t]?.alterados?.length ?? 0}</TableCell>
                    </TableRow>
                  )) : (
                    <TableRow key={`${idx}-empty`}>
                      <TableCell>{f.name}</TableCell>
                      <TableCell>{f.ip}</TableCell>
                      <TableCell colSpan={5} className="text-sm text-muted-foreground">Sem dados</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <div className="text-xs text-muted-foreground">
            Dica: baixe o JSON e suba em <code>Assessment</code> para avaliar regras.
          </div>
        </Card>
      )}
    </div>
  );
}
