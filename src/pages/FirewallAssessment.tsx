import React, { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "@/hooks/use-toast";

// Tipos mínimos para trabalhar com o JSON sem engessar o formato
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

const keyFrom = (group: string, index: number, name?: string) =>
  `${group}:${index}:${name ?? "sem-nome"}`;

const getArray = (maybeArray: any): any[] => {
  if (!maybeArray) return [];
  if (Array.isArray(maybeArray)) return maybeArray;
  if (typeof maybeArray === "object") return Object.values(maybeArray);
  return [];
};

const get = (obj: any, path: string[]) =>
  path.reduce((acc, k) => (acc && acc[k] !== undefined ? acc[k] : undefined), obj);

const FirewallAssessment: React.FC = () => {
  const [data, setData] = useState<FirewallJson | null>(null);
  const [reviews, setReviews] = useState<ReviewMap>({});
  const [tab, setTab] = useState<string>("firewall");
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // SEO básico para a página
  useEffect(() => {
    const title = "Assessment de Firewall | Análise de Regras";
    document.title = title;

    const description =
      "Faça upload do JSON de firewall, aprove/rejeite regras e adicione comentários.";

    let meta = document.querySelector('meta[name="description"]') as HTMLMetaElement | null;
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = "description";
      document.head.appendChild(meta);
    }
    meta.content = description;

    let canonical = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
    if (!canonical) {
      canonical = document.createElement("link");
      canonical.rel = "canonical";
      document.head.appendChild(canonical);
    }
    canonical.href = window.location.href;
  }, []);

  const current = data?.firewalls?.[0];

  const firewallRules = useMemo(() => {
    return getArray(get(current, ["dados", "FirewallRule"])) as any[];
  }, [current]);

  const natRules = useMemo(() => {
    return getArray(get(current, ["dados", "NATRule"])) as any[];
  }, [current]);

  const handlePickFile = () => fileInputRef.current?.click();

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const json = JSON.parse(text);
      setData(json);
      setReviews({});
      toast({
        title: "Arquivo carregado",
        description: `Encontrados ${getArray(json?.firewalls?.[0]?.dados?.FirewallRule).length} regras de firewall e ${getArray(json?.firewalls?.[0]?.dados?.NATRule).length} regras NAT`,
      });
    } catch (err: any) {
      toast({
        title: "JSON inválido",
        description: String(err?.message ?? err),
      });
    } finally {
      // limpa o input para permitir re-upload do mesmo arquivo
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const updateReview = (key: string, patch: Partial<Review>) => {
    setReviews((prev) => ({
      ...prev,
      [key]: { decision: prev[key]?.decision ?? "", comment: prev[key]?.comment ?? "", ...patch },
    }));
  };

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
    a.download = `assessment-firewall-${now}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast({ title: "Exportado com sucesso", description: "Arquivo JSON gerado." });
  };

  const clearAll = () => {
    setData(null);
    setReviews({});
    toast({ title: "Limpo", description: "Dados e avaliações foram limpos." });
  };

  const HeaderCard = (
    <Card className="p-4">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Assessment de Firewall</h1>
          <p className="text-muted-foreground">Envie o JSON exportado do firewall e avalie cada regra com decisão e comentários.</p>
        </div>
        <div className="flex gap-2">
          <Input
            ref={fileInputRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={handleFile}
          />
          <Button onClick={handlePickFile}>Upload JSON</Button>
          <Button variant="secondary" onClick={exportReviews} disabled={!data}>Exportar avaliação</Button>
          <Button variant="ghost" onClick={clearAll} disabled={!data}>Limpar</Button>
        </div>
      </header>

      {data && (
        <section className="mt-4 grid gap-3 md:grid-cols-3">
          <div className="space-y-1">
            <span className="text-sm text-muted-foreground">Execução</span>
            <div className="text-sm">{data.exec_timestamp ?? "—"}</div>
          </div>
          <div className="space-y-1">
            <span className="text-sm text-muted-foreground">Firewall</span>
            <div className="text-sm">{current?.name ?? "—"}</div>
          </div>
          <div className="space-y-1">
            <span className="text-sm text-muted-foreground">IP</span>
            <div className="text-sm">{current?.ip ?? "—"}</div>
          </div>
        </section>
      )}
    </Card>
  );

  const RulesTable: React.FC<{ rules: any[]; group: "FirewallRule" | "NATRule" }> = ({ rules, group }) => {
    if (!data) {
      return (
        <div className="text-sm text-muted-foreground">Nenhum arquivo carregado ainda.</div>
      );
    }

    if (!rules.length) {
      return (
        <div className="text-sm text-muted-foreground">Sem itens para exibir neste grupo.</div>
      );
    }

    return (
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[28%]">Regra</TableHead>
              <TableHead className="w-[10%]">IP Family</TableHead>
              <TableHead className="w-[12%]">Status</TableHead>
              <TableHead className="w-[18%]">Ação</TableHead>
              <TableHead className="w-[16%]">Decisão</TableHead>
              <TableHead>Comentário</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((rule, idx) => {
              const name = rule?.Name ?? rule?.name ?? `regra-${idx + 1}`;
              const status = rule?.Status ?? rule?.status ?? "";
              const ipf = rule?.IPFamily ?? rule?.ipFamily ?? "";
              const action =
                group === "FirewallRule"
                  ? get(rule, ["NetworkPolicy", "Action"]) ?? "—"
                  : rule?.NATMethod ?? get(rule, ["TranslatedSource"]) ?? "—";

              const k = keyFrom(group, idx, name);
              const review = reviews[k] ?? { decision: "", comment: "" };

              return (
                <TableRow key={k}>
                  <TableCell className="font-medium">{name}</TableCell>
                  <TableCell>{ipf || "—"}</TableCell>
                  <TableCell>
                    {status ? (
                      <Badge variant={status === "Enable" ? "default" : "secondary"}>{status}</Badge>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="truncate">{String(action ?? "—")}</TableCell>
                  <TableCell>
                    <Select
                      value={review.decision}
                      onValueChange={(v) => updateReview(k, { decision: v as Review["decision"] })}
                    >
                      <SelectTrigger className="w-[160px]">
                        <SelectValue placeholder="Selecionar" />
                      </SelectTrigger>
                      <SelectContent className="z-50">
                        <SelectItem value="approved">Aprovar</SelectItem>
                        <SelectItem value="rejected">Rejeitar</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell>
                    <Textarea
                      placeholder="Adicionar comentário"
                      value={review.comment}
                      onChange={(e) => updateReview(k, { comment: e.target.value })}
                      className="min-h-[36px]"
                    />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    );
  };

  return (
    <div className="container mx-auto max-w-7xl space-y-6 p-4">
      {HeaderCard}

      <main>
        <Tabs value={tab} onValueChange={setTab} defaultValue="firewall" className="space-y-4">
          <TabsList>
            <TabsTrigger value="firewall">Firewall Rules ({firewallRules.length})</TabsTrigger>
            <TabsTrigger value="nat">NAT Rules ({natRules.length})</TabsTrigger>
          </TabsList>
          <TabsContent value="firewall" className="space-y-4">
            <RulesTable rules={firewallRules} group="FirewallRule" />
          </TabsContent>
          <TabsContent value="nat" className="space-y-4">
            <RulesTable rules={natRules} group="NATRule" />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default FirewallAssessment;
