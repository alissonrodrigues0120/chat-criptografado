# Projeto: Chat Criptografado

## Visão geral

Este projeto é um protótipo de cliente/servidor para um chat com criptografia de ponta a ponta (E2EE) simulada. O servidor central **coordena** clientes, armazena chaves públicas (enviadas no registro) e roteia mensagens entre clientes. A criptografia é feita com uma combinação de **RSA** (troca de chaves) e **AES** (com modos CBC e CTR) para cifrar as mensagens.

---

## Arquitetura do sistema

- `server/serverchat.py` — servidor simples que aceita conexões TCP, registra clientes (nome + chave pública), broadcast da lista de clientes online e roteamento de mensagens (`session_key`, `encrypted_message`). Também responde a requisições de chave pública (`get_public_key`).
- `clients/client1.py`, `clients/client2.py` — implementam o cliente de chat. Realizam registro, solicitam chaves públicas ao servidor, executam troca de chave de sessão (simulada/real) e enviam/recebem mensagens cifradas.
- `criptography/` — contém os módulos criptográficos:
  - `assimetric.py` — gerenciamento de chaves RSA (geração, cifragem/decifração com PKCS1_OAEP).
  - `protocol_keys.py` — implementação do protocolo de troca de chaves (preparar e processar chaves de sessão).
  - `simetric.py` — implementação de AES nos modos CBC e CTR (manuais, usando AES-ECB como primitiva).

Como compilar/rodar:

1. Instale dependências (requer Python 3.8+):

```bash
python -m pip install pycryptodome
```

2. Inicie o servidor a partir da raiz do projeto:

```bash
python -m server.serverchat
```

3. Em terminais separados, inicie clientes (recomendado executar com `-m`):

```bash
python -m clients.client1 Alice
python -m clients.client2 Bob
```

Observação: executar como módulo (`python -m ...`) evita manipulação manual de `sys.path` e é a forma recomendada.

---

## Decisões de projeto

- Algoritmo assimétrico: **RSA 2048 bits** com PKCS#1 OAEP (via PyCryptodome). Escolhi RSA/PKCS1_OAEP pela simplicidade para a troca de chaves em um protótipo e por já estar bem suportado pela biblioteca.
- Chave de sessão: gerada aleatoriamente com `get_random_bytes(32)` (256 bits) e cifrada com a chave pública do destinatário antes de ser transmitida.
- Protocolo de troca: o cliente iniciador pede a chave pública do destinatário ao servidor (`get_public_key`). O servidor responde com `public_key`. O iniciador gera a chave de sessão, cifra-a com a chave pública do destinatário e envia (`session_key`) — o destinatário decifra com sua chave privada e passa a usar a chave simétrica.
- Formato das mensagens: JSON com chaves comuns: `type` (ex: `online_clients`, `session_key`, `encrypted_message`, `public_key`), `sender`, `recipient` e `data` (conteúdo em hex quando necessário).

Segurança (limitações): este é um protótipo didático — não há autenticação dos extremos além da posse da chave privada no cliente, nem proteção de integridade/authenticated encryption (AEAD). Em produção, use TLS, verificação de identidade (certificados), e AEAD (AES-GCM) ou use assinaturas/HMAC para integridade e autenticação.

---

## Implementação dos modos CBC e CTR

Ambos estão implementados manualmente em `criptography/simetric.py` usando a primitiva **AES-ECB** para construir os modos:

- CBC (Cipher Block Chaining):
  - Padding: **PKCS#7** via `Crypto.Util.Padding`.
  - Para cada mensagem, um IV aleatório de 16 bytes (AES.block_size) é gerado com `get_random_bytes(16)` e concatenado ao início do ciphertext (IV + ciphertext). O processo implementa a cifra e a decifra manualmente (XOR com o bloco anterior + AES-ECB).
  - Requisitos: IV aleatório e não repetido por mensagem; padding obrigatório para que a mensagem tenha múltiplos de 16 bytes.

- CTR (Counter mode):
  - Não requer padding; trata-se de um fluxo XOR entre a mensagem e a sequência gerada cifrando blocos de nonce+contador.
  - Nonce: 8 bytes aleatórios (64 bits) gerados com `get_random_bytes(8)` quando o modo é selecionado. Counter (64 bits) é incrementado para cada mensagem e é serializado em big-endian (`struct.pack('>Q', counter)`).
  - Formato do ciphertext: `nonce (8 bytes)` + `initial_counter (8 bytes)` + `encrypted_data`.

Observação: ambas as implementações usam AES-ECB somente como bloco básico para construir os modos e não devem ser substitutas para bibliotecas testadas em produção (prefira usar modos nativos/implementações certificadas quando disponível).

---

## Comparação rápida: CBC vs CTR

| Aspecto | CBC | CTR |
|---|---:|---:|
| Necessidade de padding | Sim (PKCS#7) | Não |
| Requisito de IV/Nonce | IV aleatório por mensagem (16 bytes) | Nonce único + contador (nonce 8 bytes + counter 8 bytes) |
| Paralelização de encriptação | Não (encadeado) | Sim (por blocos) |
| Complexidade de implementação | Moderada (devido a padding) | Moderada (devido a contador e gerenciamento de nonce) |
| Vulnerabilidades a se atentar | IV repetido/prevísivel, padding oracle se não tratado | Nonce repetido leva à reutilização de stream (desastroso) |

---

## Formato de mensagens e interoperabilidade

- `online_clients` (enviado pelo servidor): `{ "type": "online_clients", "clients": ["Alice","Bob"], "sender": "SERVER" }`.
- `get_public_key` (cliente -> servidor): `{ "type": "get_public_key", "recipient": "Bob" }`.
- `public_key` (servidor -> cliente): `{ "type": "public_key", "recipient": "Bob", "data": "<PEM public key>" }`.
- `session_key` (iniciador -> receptor via servidor): `{ "type": "session_key", "recipient": "Bob", "data": "<hex do ciphertext RSA>" }`.
- `encrypted_message` (cliente -> cliente via servidor): `{ "type": "encrypted_message", "recipient": "Bob", "data": "<hex do ciphertext>" }`.

O receptor aceita `session_key` cifradas com RSA e também, para fins de simulação, `session_key` enviadas em hex (chave simétrica em claro). A implementação registra e valida formatos para evitar erros de parsing.

---

## Como testar / Debug

- Logs de debug: os clientes imprimem `RAW RECEIVED: ...` para facilitar a inspeção do JSON recebido e detectar problemas de formato.
- Fluxo de teste sugerido: inicie servidor; conecte dois clientes; no cliente A execute `connect B` seguido de uma mensagem; observe o handshake de troca de chave e o envio de mensagens cifradas.


