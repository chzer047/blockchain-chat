# 🔐 Chat Seguro — Blockchain

Chat criptografado baseado em blockchain local. Sem servidor central. Sem nome real registrado.

## Como usar

```bash
pip install -r requirements.txt
streamlit run app.py
```

1. Abra o app no navegador
2. Digite um **apelido** e o **código de sala**
3. Compartilhe o código com sua equipe **fora do app** (WhatsApp, pessoalmente, etc.)
4. Todos que entrarem com o mesmo código conseguem ler as mensagens

## O que é criptografado

| Campo | Situação |
|---|---|
| Texto da mensagem | ✅ Cifrado (AES-256-GCM) |
| Apelido | ✅ Cifrado (AES-256-GCM) |
| Endereço de carteira | Hash anônimo da chave pública |
| Horário | Visível no bloco |

## Identidade persistente

Exporte sua chave privada (.pem) pela barra lateral para manter o mesmo endereço de carteira entre sessões.

## Tecnologias

- **AES-256-GCM** — cifração das mensagens e nicknames
- **PBKDF2-SHA256** (200k iterações) — derivação da chave de sala
- **RSA-2048 + PSS** — assinatura de cada bloco
- **SHA-256** — encadeamento dos blocos (integridade)
