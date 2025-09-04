import requests
import xml.etree.ElementTree as ET
import json
import os
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Desabilita os avisos de requisições SSL não verificadas
urllib3.disable_warnings(InsecureRequestWarning)

# --- CONFIGURAÇÕES GLOBAIS ---
OUTPUT_DIR = "output"
HISTORY_DIR = "history"
JSON_UNIC_FILE = os.path.join(OUTPUT_DIR, "firewalls_data.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(HISTORY_DIR, exist_ok=True)


def get_timestamp():
    """Retorna o timestamp atual formatado para exibição."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_timestamp_for_filename():
    """Retorna o timestamp atual formatado para ser usado em nomes de arquivo."""
    return datetime.now().strftime("%Y-%m-%dT%H-%M-%S")


def consultar_sophos_api(firewall_config, tipos_consulta):
    """
    Envia uma requisição para a API do Sophos para obter dados de configuração.
    """
    get_tags = "\n".join([f"<{tipo}></{tipo}>" for tipo in tipos_consulta])
    reqxml = f"""
    <Request>
        <Login>
            <Username>{firewall_config['username']}</Username>
            <Password>{firewall_config['password']}</Password>
        </Login>
        <Get>
            {get_tags}
        </Get>
    </Request>
    """.strip()
    url = f"https://{firewall_config['ip']}:{firewall_config['port']}/webconsole/APIController"
    try:
        print(f"  - Conectando em {firewall_config['name']} ({firewall_config['ip']} )...")
        response = requests.post(
            url,
            headers={"Accept": "application/xml"},
            files={"reqxml": (None, reqxml)},
            verify=False,
            timeout=45
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha ao consultar {', '.join(tipos_consulta)} de {firewall_config['name']} ({firewall_config['ip']}): {e}")
        return ""

def parse_element_to_dict(element):
    """
    Função recursiva para converter um elemento XML e seus filhos em um dicionário.
    Lida com tags aninhadas e listas de tags com o mesmo nome.
    """
    result = {}
    for child in element:
        child_data = parse_element_to_dict(child)
        # Se o filho não tem mais filhos, mas tem texto, pegue o texto.
        if not child_data and child.text:
            child_data = child.text.strip()
        
        # Se a tag já existe, transforma em uma lista.
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]  # Converte para lista
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data
            
    # Se o elemento não tem filhos, mas tem texto, retorna o texto.
    if not result and element.text and element.text.strip():
        return element.text.strip()
        
    return result

def parsear_firewall_rule(xml_text):
    """
    Função especializada para parsear a tag 'FirewallRule', que tem
    uma estrutura complexa com políticas aninhadas.
    """
    try:
        root = ET.fromstring(xml_text)
        rules = []
        for rule_element in root.findall(".//FirewallRule"):
            rule_data = parse_element_to_dict(rule_element)
            if rule_data:
                rules.append(rule_data)
        return rules
    except ET.ParseError as e:
        print(f"[ERRO] Falha ao parsear XML para a tag 'FirewallRule': {e}")
        return []

def parsear_webfilter_urlgroup(xml_text):
    """
    Função especializada para parsear a tag 'WebFilterURLGroup'.
    """
    try:
        root = ET.fromstring(xml_text)
        grupos = []
        for group_element in root.findall(".//WebFilterURLGroup"):
            group_data = parse_element_to_dict(group_element)
            if group_data:
                grupos.append(group_data)
        return grupos
    except ET.ParseError as e:
        print(f"[ERRO] Falha ao parsear XML para a tag 'WebFilterURLGroup': {e}")
        return []

def parsear_webfilter_policy(xml_text):
    """
    Função especializada para parsear a tag 'WebFilterPolicy'.
    """
    try:
        root = ET.fromstring(xml_text)
        policies = []
        for policy_element in root.findall(".//WebFilterPolicy"):
            policy_data = parse_element_to_dict(policy_element)
            if policy_data:
                policies.append(policy_data)
        return policies
    except ET.ParseError as e:
        print(f"[ERRO] Falha ao parsear XML para a tag 'WebFilterPolicy': {e}")
        return []

def parsear_generico(xml_text, tag):
    """
    Analisa uma string XML e extrai os dados de uma tag específica (estrutura simples).
    """
    try:
        root = ET.fromstring(xml_text)
        items_encontrados = []
        for elemento in root.findall(f".//{tag}"):
            item_dict = parse_element_to_dict(elemento)
            if item_dict:
                items_encontrados.append(item_dict)
        return items_encontrados
    except ET.ParseError as e:
        print(f"[ERRO] Falha ao parsear XML para a tag '{tag}': {e}")
        return []

def salvar_dados_em_json(data, path):
    """
    Salva um dicionário em um arquivo JSON com formatação legível.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except IOError as e:
        print(f"[ERRO] Não foi possível salvar o arquivo JSON em {path}: {e}")

def processar_tipos_de_consulta(firewall_config, tipos_consulta):
    """
    Processa um grupo de tipos de consulta para um firewall específico,
    usando a função de parsing apropriada para cada tipo.
    """
    print(f"  - Consultando: {', '.join(tipos_consulta)}")
    xml_response = consultar_sophos_api(firewall_config, tipos_consulta)
    if not xml_response:
        return {}

    resultados = {}
    for tipo in tipos_consulta:
        # Dicionário de mapeamento de tipos para funções de parsing especializadas
        parser_map = {
            'WebFilterURLGroup': parsear_webfilter_urlgroup,
            'WebFilterPolicy': parsear_webfilter_policy,
            'FirewallRule': parsear_firewall_rule
        }
        # Seleciona a função de parsing correta ou a genérica
        parser_func = parser_map.get(tipo, parsear_generico)
        dados = parser_func(xml_response) if parser_func == parsear_generico else parser_func(xml_response, tipo)

        resultados[tipo] = dados
    return resultados

def processar_firewall(firewall_config, exec_timestamp):
    """
    Orquestra a coleta de todas as informações de um único firewall.
    """
    print(f"\nProcessando firewall: {firewall_config['name']}...")
    
    dados_coletados_firewall = {
        "name": firewall_config["name"],
        "ip": firewall_config["ip"],
        "coletado_em": exec_timestamp,
        "dados": {}
    }

    grupos_de_consulta = [
        ["AdminSettings", "BackupRestore", "SNMPCommunity", "AuthenticationServer", "User"],
        ["Zone", "Interface", "VLAN", "Alias", "XFRMInterface", "DHCPServer", "DNS"],
        ["FirewallRuleGroup", "FirewallRule", "NATRule", "WebFilterURLGroup", "WebFilterPolicy", "ApplicationFilterPolicy"],
        ["GatewayConfiguration", "RouterAdvertisement", "UnicastRoute", "SDWANProfile", "SDWANPolicyRoute", "VPNIPSecConnection"],
        ["IPHost", "Services", "MACHost", "FQDNHost", "LocalServiceACL"]
    ]

    for grupo in grupos_de_consulta:
        # Passa o tipo de consulta para a função de parsing genérica
        resultados_grupo = {}
        xml_response = consultar_sophos_api(firewall_config, grupo)
        if not xml_response:
            continue

        for tipo in grupo:
            parser_map = {
                'WebFilterURLGroup': parsear_webfilter_urlgroup,
                'WebFilterPolicy': parsear_webfilter_policy,
                'FirewallRule': parsear_firewall_rule
            }
            parser_func = parser_map.get(tipo, parsear_generico)
            
            # A função genérica precisa do nome da tag, as outras não
            if parser_func == parsear_generico:
                dados = parser_func(xml_response, tipo)
            else:
                dados = parser_func(xml_response)

            resultados_grupo[tipo] = dados
        
        dados_coletados_firewall["dados"].update(resultados_grupo)

    return dados_coletados_firewall

def main():
    """
    Função principal que executa o fluxo de coleta de dados.
    """
    print("Iniciando o script de coleta de dados do Sophos...")

    try:
        with open("firewalls.json", "r", encoding="utf-8") as f:
            firewalls = json.load(f)
    except FileNotFoundError:
        print("[ERRO] Arquivo 'firewalls.json' não encontrado. Crie o arquivo com a lista de firewalls.")
        return
    except json.JSONDecodeError:
        print("[ERRO] Arquivo 'firewalls.json' está mal formatado.")
        return

    exec_timestamp_str = get_timestamp()
    
    resultado_final = {
        "exec_timestamp": exec_timestamp_str,
        "firewalls": []
    }

    for fw in firewalls:
        dados_firewall = processar_firewall(fw, exec_timestamp_str)
        
        if dados_firewall["dados"]:
            resultado_final["firewalls"].append(dados_firewall)
            timestamp_arquivo = get_timestamp_for_filename()
            nome_arquivo_hist = f"{fw['name']}_{timestamp_arquivo}.json"
            caminho_hist = os.path.join(HISTORY_DIR, nome_arquivo_hist)
            salvar_dados_em_json(dados_firewall, caminho_hist)
            print(f"  -> Histórico salvo em: {caminho_hist}")
        else:
            print(f"  -> Não foi possível coletar dados para {fw['name']}. Pulando.")

    if resultado_final["firewalls"]:
        salvar_dados_em_json(resultado_final, JSON_UNIC_FILE)
        print(f"\n✅ Arquivo JSON único gerado com sucesso em: {JSON_UNIC_FILE}")
    else:
        print("\nNenhum dado de firewall foi coletado. Nenhum arquivo JSON único foi gerado.")

    print("\nScript finalizado.")


if __name__ == "__main__":
    main()
