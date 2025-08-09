import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { Shield, LogIn } from "lucide-react";

const Login = () => {
  const navigate = useNavigate();
  const { toast } = useToast();

  useEffect(() => {
    document.title = "Login — RUACH • Report by Zabbix";
    const meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute("content", "Faça login no RUACH — Report by Zabbix e acesse o dashboard para gerar e agendar relatórios do Zabbix.");
  }, []);

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    toast({ title: "Bem-vindo(a) ao RUACH", description: "Login de demonstração concluído." });
    navigate("/dashboard");
  }

  return (
    <div className="min-h-screen grid md:grid-cols-2 relative isolate">
      {/* Left brand panel */}
      <aside className="hidden md:flex flex-col justify-between p-10 bg-secondary text-secondary-foreground relative overflow-hidden">
        <div className="absolute -top-24 -left-24 h-72 w-72 rounded-full bg-primary/20 blur-2xl animate-[drift_10s_ease-in-out_infinite]" aria-hidden />
        <div className="absolute -bottom-16 -right-16 h-60 w-60 rounded-full bg-accent/20 blur-2xl animate-[drift_12s_ease-in-out_infinite]" aria-hidden />
        <div>
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-xl bg-primary/20 grid place-items-center ring-1 ring-primary/40">
              <Shield className="h-6 w-6 text-primary" aria-hidden />
            </div>
            <div className="leading-tight">
              <span className="block text-sm opacity-80">RUACH</span>
              <span className="block font-heading text-2xl tracking-wide">Report by Zabbix</span>
            </div>
          </div>
          <p className="mt-6 max-w-md text-muted-foreground">
            Infraestrutura, segurança e análise de dados — clareza para decisões inteligentes.
          </p>
        </div>

        <div className="text-sm text-muted-foreground">
          © {new Date().getFullYear()} RUACH. Todos os direitos reservados.
        </div>
      </aside>

      {/* Right form */}
      <main className="flex items-center justify-center p-6 md:p-10">
        <Card className="w-full max-w-md shadow-lg">
          <CardHeader>
            <h1 className="font-heading text-3xl leading-none tracking-tight">Entrar no RUACH</h1>
            <CardDescription>
              Acesse o dashboard para gerar e agendar relatórios do Zabbix.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-5" onSubmit={handleSubmit}>
              <div className="grid gap-2">
                <Label htmlFor="email">E-mail</Label>
                <Input id="email" name="email" type="email" placeholder="voce@empresa.com" required autoComplete="email" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="password">Senha</Label>
                <Input id="password" name="password" type="password" required autoComplete="current-password" />
              </div>

              <div className="flex items-center justify-between text-sm">
                <a href="#" className="text-primary underline-offset-4 hover:underline">Esqueci minha senha</a>
              </div>

              <Button type="submit" variant="hero" className="w-full">
                <LogIn className="mr-1" /> Entrar
              </Button>

              <p className="text-xs text-muted-foreground">
                Ao continuar, você concorda com os termos de uso e política de privacidade.
              </p>
            </form>
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

export default Login;
