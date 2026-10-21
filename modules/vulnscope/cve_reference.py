"""
modules/vulnscope/cve_reference.py

Base de referência LOCAL e ILUSTRATIVA de vulnerabilidades amplamente
conhecidas e publicamente documentadas, usada pelo PC VulnScope para
gerar HIPÓTESES de correlação (não confirmações). Os dados aqui são
resumos de domínio público (CVEs famosos, já corrigidos há anos na
maioria dos casos) incluídos apenas para fins educacionais e de
treinamento em CTF/laboratório.

Esta base é deliberadamente pequena. Para uso real, sempre consulte
fontes oficiais: https://nvd.nist.gov/ e https://cve.mitre.org/.
Faixas de versão são aproximadas e podem não refletir todos os
backports de segurança feitos por distribuições Linux.
"""

from __future__ import annotations

CVE_REFERENCE_DB: dict[str, list[dict]] = {
    "openssh": [
        {
            "cve_id": "CVE-2018-15473",
            "description": "Enumeração de usuários válidos via timing/resposta diferenciada na autenticação.",
            "min_version": None,
            "max_version": (7, 7),
            "severity": "baixa",
            "recommendation": "Atualizar para uma versão corrigida do OpenSSH e revisar configuração de autenticação.",
        },
    ],
    "vsftpd": [
        {
            "cve_id": "CVE-2011-2523",
            "description": (
                "Versão com backdoor conhecido introduzido maliciosamente nos "
                "arquivos de distribuição (vsftpd 2.3.4), permitindo execução "
                "remota de comandos via string de login específica."
            ),
            "min_version": (2, 3, 4),
            "max_version": (2, 3, 4),
            "severity": "crítica",
            "recommendation": "Jamais usar vsftpd 2.3.4 obtido de fontes não oficiais; reinstalar de repositório confiável.",
        },
    ],
    "apache": [
        {
            "cve_id": "CVE-2021-41773",
            "description": "Path traversal e possível execução remota de código no Apache HTTP Server 2.4.49.",
            "min_version": (2, 4, 49),
            "max_version": (2, 4, 49),
            "severity": "crítica",
            "recommendation": "Atualizar para 2.4.51 ou superior; revisar 'require all denied' em cgi-bin.",
        },
    ],
    "openssl": [
        {
            "cve_id": "CVE-2014-0160",
            "description": "Heartbleed — leitura de memória fora dos limites via extensão heartbeat do TLS.",
            "min_version": (1, 0, 1),
            "max_version": (1, 0, 1),
            "severity": "crítica",
            "recommendation": "Atualizar OpenSSL, revogar e reemitir certificados potencialmente expostos.",
        },
    ],
    "bash": [
        {
            "cve_id": "CVE-2014-6271",
            "description": "Shellshock — execução de comandos arbitrários via variáveis de ambiente especialmente formatadas.",
            "min_version": None,
            "max_version": (4, 3),
            "severity": "crítica",
            "recommendation": "Atualizar bash para versão corrigida; auditar scripts CGI e handlers que usam variáveis de ambiente.",
        },
    ],
    "smb": [
        {
            "cve_id": "CVE-2017-0144",
            "description": "EternalBlue — execução remota de código no SMBv1 do Windows (não se aplica a Samba por padrão).",
            "min_version": None,
            "max_version": None,
            "severity": "crítica",
            "recommendation": "Desabilitar SMBv1; aplicar patches MS17-010 em sistemas Windows.",
        },
    ],
    "log4j": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell — execução remota de código via JNDI lookup em mensagens de log não sanitizadas.",
            "min_version": (2, 0),
            "max_version": (2, 14, 1),
            "severity": "crítica",
            "recommendation": "Atualizar para Log4j 2.17.1+; remover JndiLookup do classpath como mitigação temporária.",
        },
    ],
    "struts": [
        {
            "cve_id": "CVE-2017-5638",
            "description": "Execução remota de código via cabeçalho Content-Type malformado no Apache Struts 2 (Jakarta Multipart parser).",
            "min_version": (2, 3, 5),
            "max_version": (2, 3, 31),
            "severity": "crítica",
            "recommendation": "Atualizar Struts para versão corrigida; validar parsing de upload multipart.",
        },
    ],
}
