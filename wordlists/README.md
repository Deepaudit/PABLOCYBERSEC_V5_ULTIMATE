# Wordlists

Este diretório é onde você coloca suas próprias wordlists para uso no
**PC HashLab** (teste de senha contra hash) e em outros módulos que
aceitem listas personalizadas (como o **PC WebHunter**, para enumeração
de caminhos).

## Importante

- **Nenhuma wordlist é distribuída com o projeto.** Isso é intencional:
  o repositório não inclui arquivos de terceiros, listas gigantes nem
  dados de senhas reais vazadas.
- Use apenas wordlists que você tem direito de usar (criadas por você,
  ou de fontes com licença compatível, como as listas do projeto
  [SecLists](https://github.com/danielmiessler/SecLists)).
- Wordlists grandes não devem ser commitadas no Git — este diretório
  já está listado no `.gitignore` (exceto este README).

## Formato esperado

Um arquivo de texto simples, uma palavra/candidato por linha:

```
123456
password
admin123
senha_do_desafio
```

## Como usar

1. Baixe ou crie sua wordlist e salve-a aqui, por exemplo:
   `wordlists/rockyou_sample.txt`
2. No menu principal, acesse `[02] HashLab` → `[6] Testar senha em
   wordlist`.
3. Informe o hash alvo, o algoritmo e o caminho da wordlist (pode ser
   relativo a este diretório ou um caminho absoluto).

## Limites de segurança

Por padrão, a PABLOCYBERSEC V5 processa no máximo
`hash_wordlist_max_lines` linhas (configurável em `config/settings.json`,
padrão: 2.000.000) para evitar consumo excessivo de tempo/memória em
wordlists muito grandes. Ajuste esse limite nas Configurações do menu
principal se precisar processar listas maiores.
