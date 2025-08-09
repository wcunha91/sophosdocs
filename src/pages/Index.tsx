// Landing simplificada direcionando para o Login
import { Button } from "@/components/ui/button";

const Index = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4 px-6">
        <h1 className="font-heading text-4xl md:text-5xl">RUACH — Report by Zabbix</h1>
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
          Infraestrutura, segurança e análise de dados. Gere e agende relatórios do Zabbix com clareza e precisão.
        </p>
        <div className="flex items-center justify-center gap-4">
          <a href="/login"><Button variant="hero">Entrar</Button></a>
          <a href="/dashboard"><Button variant="outline">Ver Dashboard (demo)</Button></a>
        </div>
      </div>
    </div>
  );
};

export default Index;
