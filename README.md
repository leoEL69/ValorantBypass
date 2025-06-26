# 🛡️ Vanguard TPM Popup Bypass Tool

Este projeto em C++ automatiza o bypass da proteção de **TPM/HVCI do Vanguard (Riot Anti-Cheat)**, impedindo o fechamento automático do jogo Valorant causado por falta de Secure Boot ou TPM.

> ⚠️ **Atenção**: Este projeto é estritamente para fins educacionais e de pesquisa em segurança. O uso indevido para trapacear em jogos online viola os termos de serviço e pode resultar em banimento ou consequências legais.

---

## 🧠 Como Funciona

- Detecta o processo `VALORANT-Win64-Shipping.exe`.
- Habilita `SeDebugPrivilege` para controle de processos protegidos.
- Finaliza e configura o serviço `vgc` como manual.
- Aguarda 20 segundos para injeção de DLLs ou load externo.
- Realiza o bypass do popup de TPM localizando o `svchost.exe` com `tpmcore.dll` carregado e suspendendo-o via `pssuspend.exe`.
- Monitora o processo `vgm.exe` e o suspende periodicamente para evitar revalidações do anti-cheat.

---

## 🛠️ Pré-Requisitos

- Compilador C++ (Visual Studio recomendado)
- Executar como **Administrador**
- Windows 10/11
- TPM desativado ou Secure Boot desativado
- [PsSuspend.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend) (coloque na mesma pasta do .exe)

