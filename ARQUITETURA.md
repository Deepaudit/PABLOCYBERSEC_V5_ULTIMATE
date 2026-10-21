# Notas de Arquitetura — PABLOCYBERSEC V5

Este documento complementa a seção "Arquitetura" do `README.md` com
detalhes de implementação úteis para quem for estender a plataforma.

## Padrão de módulo

Todo módulo em `modules/<nome>/` separa:

- **`engine.py`** — lógica pura (funções e dataclasses), sem nenhuma
  chamada a `input()`/`print()`. Testável diretamente pelo pytest sem
  simular terminal.
- **`menu.py`** — camada de interface, expõe `run_interactive(ui,
  settings, reporter)`. Converte entrada de terminal em chamadas ao
  `engine.py` e formata a saída usando `core.ui.UI`.

O `cli.py` descobre e importa `modules.<nome>.menu` dinamicamente a
partir da lista `MODULES`, e trata qualquer exceção não prevista de
um módulo sem derrubar o processo principal (ver `run_module()`).

## Por que núcleo mínimo (`core/`)

O núcleo foi mantido deliberadamente pequeno:

- `config.py` — uma única fonte de verdade para limites operacionais
  (timeouts, concorrência, limites de tamanho), carregada de
  `config/settings.json` com fallback para padrões conservadores.
- `logger.py` — logging centralizado com um filtro de redação de
  valores sensíveis (`RedactingFilter`), aplicado antes de qualquer
  escrita em disco.
- `report.py` — um índice JSON simples (`reports/index.json`) mais um
  arquivo por relatório, suficiente para o volume de uso de um CTF,
  sem necessidade de banco de dados.
- `ui.py` — wrapper fino sobre `print`/`input`, com detecção de
  suporte a cores (`NO_COLOR`/`PABLOCYBERSEC_NO_COLOR` respeitados).
- `utils.py` — validação de alvos/portas e `safe_path()` para evitar
  path traversal em qualquer módulo que aceite um caminho de arquivo
  fornecido pelo usuário (ex.: wordlist no PC HashLab).

## Decisões de segurança incorporadas na arquitetura

- Módulos que fazem conexões de rede ativas (`recon`, `netcore`,
  `webhunter`) sempre passam por uma confirmação explícita de
  autorização no `menu.py` **antes** de chamar qualquer função de rede
  do `engine.py`. O `engine.py` em si não pede confirmação — isso é
  intencional, para que a lógica pura permaneça testável sem mockar
  `input()`, mas significa que qualquer novo ponto de entrada para
  esses módulos **deve** replicar a confirmação.
- `modules/linuxenum/engine.py` não contém nenhuma chamada de escrita
  de arquivo (`open(..., "w")` etc.) — isso é verificado também por um
  teste automatizado (`tests/test_linuxenum.py::test_engine_module_has_no_write_operations`)
  que falha caso um padrão de escrita seja introduzido no futuro.
- `modules/forensics/engine.py` idem: todas as funções abrem arquivos
  apenas em modo leitura (`"rb"`), preservando evidências.
- `modules/flaghunter/engine.py` não gera valores de flag — apenas
  casa padrões regex contra texto fornecido. A confirmação de flag
  (`confirm_flag()`) é uma função separada, chamada apenas quando o
  usuário fornece explicitamente o valor e uma descrição da evidência.

## Extensão futura sugerida (não implementada nesta versão)

- CLI com argumentos por módulo (ex.: `pablocybersec recon --target X`),
  mantendo o menu interativo como modo padrão.
- Persistência opcional dos relatórios em SQLite para volumes maiores.
- Captura de tráfego ao vivo no PC PacketLab, com verificação de
  privilégio já preparada em `check_raw_capture_privileges()`.
