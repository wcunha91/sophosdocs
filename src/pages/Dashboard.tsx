import { SidebarProvider, Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarSeparator, SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { Home, PlayCircle, CalendarClock, FileText, Settings, Shield } from "lucide-react";
import { useEffect } from "react";

const Dashboard = () => {
  const { toast } = useToast();

  useEffect(() => {
    document.title = "Dashboard — RUACH • Report by Zabbix";
  }, []);

  const actions = [
    { key: "generate", title: "Gerar Relatório", desc: "Crie relatórios personalizados do Zabbix.", icon: PlayCircle },
    { key: "scheduled", title: "Relatórios Agendados", desc: "Gerencie agendamentos e periodicidades.", icon: CalendarClock },
    { key: "generated", title: "Relatórios Gerados", desc: "Acesse o histórico de relatórios.", icon: FileText },
    { key: "settings", title: "Configurações", desc: "Ajuste integrações e preferências.", icon: Settings },
  ];

  const handleAction = (key: string) => {
    toast({ title: "Em breve", description: `Ação "${key}" (demo).` });
  };

  return (
    <SidebarProvider>
      <Sidebar variant="sidebar" collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center gap-2 px-2 py-1">
            <div className="h-8 w-8 rounded-md bg-primary/20 grid place-items-center ring-1 ring-primary/40">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <div className="text-sm leading-tight">
              <span className="block font-heading">RUACH</span>
              <span className="text-[11px] opacity-80">Report by Zabbix</span>
            </div>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Navegação</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <button type="button"><Home /> Início</button>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <button type="button" onClick={() => handleAction("generate")}><PlayCircle /> Gerar Relatório</button>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <button type="button" onClick={() => handleAction("scheduled")}><CalendarClock /> Relatórios Agendados</button>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <button type="button" onClick={() => handleAction("generated")}><FileText /> Relatórios Gerados</button>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <button type="button" onClick={() => handleAction("settings")}><Settings /> Configurações</button>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarSeparator />
        <SidebarFooter>
          <div className="px-2 text-xs opacity-75">v0.1.0</div>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset>
        <header className="flex h-14 items-center gap-2 border-b px-4">
          <SidebarTrigger />
          <div className="ml-1 font-heading">Dashboard</div>
        </header>
        <div className="p-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {actions.map((a) => {
            const Icon = a.icon;
            return (
              <Card key={a.key} className="hover:shadow-lg transition-shadow">
                <CardHeader className="flex flex-row items-center gap-3">
                  <div className="h-10 w-10 rounded-md bg-primary/15 text-primary grid place-items-center">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <CardTitle className="font-heading text-xl">{a.title}</CardTitle>
                    <CardDescription>{a.desc}</CardDescription>
                  </div>
                </CardHeader>
                <CardContent>
                  <Button variant="hero" onClick={() => handleAction(a.key)}>Acessar</Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
};

export default Dashboard;
