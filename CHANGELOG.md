# Changelog

Todas as mudanças notáveis deste projeto são documentadas neste arquivo.

O formato segue aproximadamente [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto usa versionamento no estilo [SemVer](https://semver.org/lang/pt-BR/).

## [5.0.0] — 2025

### Adicionado
- Primeira versão pública da PABLOCYBERSEC V5.
- Núcleo comum (`core/`): configuração centralizada, logging com redação de
  dados sensíveis, sistema de relatórios/histórico em JSON, interface de
  terminal com cores/banners/menus/tabelas, utilidades de validação de
  entrada (alvos, portas, proteção contra path traversal).
- **PC Recon** (Módulo 01): descoberta de hosts, varredura de portas TCP
  assíncrona com controle de concorrência, banner grabbing básico,
  resolução DNS (A/AAAA/PTR).
- **PC HashLab** (Módulo 02): identificação heurística de formato de hash,
  cálculo de hash de texto/arquivo (MD5, SHA-1/224/256/384/512, SHA-3,
  BLAKE2), comparação segura, verificação de integridade, teste de senha
  contra wordlist com limites configuráveis e indicador de progresso.
- **PC CipherLab** (Módulo 03): Base64, Base32, hexadecimal, URL encoding,
  binário, ROT13, cifra de César (deslocamento único ou força bruta),
  cifra de Vigenère, XOR (chave conhecida ou força bruta de 1 byte),
  análise de frequência de letras, detecção heurística de formato.
- **PC NetCore** (Módulo 04): teste de conectividade TCP, listener e
  cliente TCP simples, transferência de arquivos com limite de tamanho.
  Execução remota de comandos não implementada por design.
- **PC WebHunter** (Módulo 05): inspeção de cabeçalhos HTTP, cookies,
  redirecionamentos, certificados TLS, detecção de tecnologias por
  evidência observável, análise de cabeçalhos de segurança ausentes,
  enumeração de diretórios/caminhos com lista personalizável.
- **PC VulnScope** (Módulo 06): correlação de serviço+versão com uma base
  local e ilustrativa de CVEs conhecidos, sempre classificada como
  hipótese (nunca confirmação automática), com recomendações.
- **PC LinuxEnum** (Módulo 07): enumeração local somente leitura
  (usuário atual, sudo, SUID/SGID, cron, portas, processos, interfaces
  de rede), com perfis "básico" e "completo".
- **PC Forensics** (Módulo 08): identificação de tipo real de arquivo por
  assinatura (detecta mismatch com a extensão declarada), cálculo de
  hashes/metadados, listagem de conteúdo ZIP, extração de strings,
  busca por regex, hex dump. Preserva sempre o arquivo original.
- **PC PacketLab** (Módulo 09): análise de PCAP via Scapy (opcional, com
  verificação de disponibilidade), fallback de leitura de cabeçalho PCAP
  sem dependências externas, verificação de privilégios para captura
  ao vivo (sem realizar a captura).
- **PC FlagHunter** (Módulo 10): detecção de padrões de flag conhecidos em
  texto fornecido, cadernos de caso persistentes com hipóteses e
  evidências, confirmação de flag sempre manual e com evidência exigida.
- Interface de terminal unificada (`cli.py`) com menu principal, verificação
  de dependências, configurações editáveis, histórico de relatórios e ajuda.
- Instalador (`install.sh`) com detecção de distribuição, verificação de
  Python 3.10+, criação de ambiente virtual e instalação de dependências
  opcionais. Desinstalador (`uninstall.sh`) com remoção confirmada por item.
- Suíte de testes automatizados com `pytest` cobrindo todos os 10 módulos.

### Limitações conhecidas desta versão
- PC Recon não realiza varredura SYN "stealth" nem fingerprinting de SO;
  é uma varredura de conexão TCP completa (connect scan).
- PC VulnScope usa uma base de referência local pequena e ilustrativa —
  não substitui consulta a fontes oficiais (NVD, MITRE, fornecedor).
- PC PacketLab requer Scapy para análise completa de pacotes; sem ela,
  apenas o cabeçalho do arquivo PCAP clássico é lido.
- PC NetCore não implementa execução remota de comandos (por design).
- Testes de disponibilidade de host (PC Recon) usam sondas TCP, não ICMP
  puro, por não exigirem privilégios root — podem gerar falsos negativos
  contra hosts com firewall muito restritivo.
