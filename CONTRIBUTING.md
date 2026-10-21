# Contribuindo com a PABLOCYBERSEC V5

Obrigado por considerar contribuir com o projeto! Este guia resume como
propor mudanças de forma consistente com a arquitetura existente.

## Princípios do projeto

1. **Honestidade técnica acima de tudo.** Nenhum módulo deve alegar fazer
   mais do que realmente faz. Se uma funcionalidade depende de uma
   biblioteca opcional, o código deve verificar sua disponibilidade e
   informar claramente quando ela está ausente — nunca falhar em silêncio
   nem fingir sucesso.
2. **Escopo educacional e autorizado.** Novas funcionalidades devem servir
   a CTFs, laboratórios e auditorias autorizadas. Não serão aceitas
   contribuições que implementem ransomware, roubo de credenciais,
   persistência clandestina, evasão de detecção, propagação automática
   ou exploração indiscriminada de terceiros.
3. **Segurança por padrão.** Módulos ativos (que fazem conexões de rede
   reais) devem exigir confirmação explícita de escopo antes de agir.
   Operações potencialmente destrutivas devem pedir confirmação. Nenhuma
   função deve escrever fora dos diretórios do projeto sem necessidade.

## Estrutura esperada de um módulo

Cada módulo em `modules/<nome>/` deve conter, no mínimo:

```
modules/<nome>/
├── __init__.py
├── engine.py   # lógica pura, testável sem interação de terminal
└── menu.py     # integração com a interface (run_interactive)
```

`menu.py` deve expor:

```python
def run_interactive(ui: UI, settings: Settings, reporter: ReportManager) -> None:
    ...
```

Isso mantém a lógica de negócio (`engine.py`) desacoplada da interface,
facilitando testes automatizados sem simular entrada de terminal.

## Como propor uma mudança

1. Abra uma *issue* descrevendo o problema ou a funcionalidade proposta.
2. Faça um fork e crie um branch descritivo (`feature/nome-da-mudanca`).
3. Escreva ou atualize os testes em `tests/` cobrindo a mudança.
4. Rode a suíte de testes localmente antes de abrir o Pull Request:
   ```bash
   .venv/bin/pip install -r requirements-dev.txt
   .venv/bin/pytest
   ```
5. Atualize o `README.md` e o `CHANGELOG.md` se a mudança afetar
   funcionalidades documentadas.
6. Abra o Pull Request descrevendo o que mudou e por quê.

## Estilo de código

- Python 3.10+, com *type hints* sempre que praticável.
- Mensagens de interface (prints, prompts) em português brasileiro.
- Docstrings e comentários explicando *decisões de segurança/escopo*,
  não apenas o que o código faz.
- Evite dependências novas quando a biblioteca padrão resolver o problema.
  Se uma dependência for realmente necessária, torne-a opcional sempre
  que possível (verificação de disponibilidade + fallback claro).

## Relatando problemas de segurança

Se você encontrar uma vulnerabilidade na própria ferramenta (não nos
alvos que ela analisa), por favor não abra uma *issue* pública. Entre em
contato diretamente com os mantenedores do repositório.
