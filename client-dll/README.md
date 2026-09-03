# Proteção do Cliente Lineage 2 (Interlude / 41x) — DLL proxy `ogg.dll`

Este projeto gera uma **`ogg.dll`** que vai na pasta `system/` do cliente e faz
o **decrypt on-the-fly** dos seus arquivos (`.dat`, `.u`, `.ukx`, `.utx`) usando
**Blowfish + a sua chave privada**.

Como a chave fica **apenas na sua DLL e no seu encryptor**, ferramentas de
terceiros (ex.: SmartCrypt) **não conseguem** decriptar seus arquivos — elas não
têm a sua chave.

---

## Como funciona (visão geral)

```
Encryptor (C#)  --Blowfish+chave-->  arquivos .dat cifrados  -->  client/system/
                                                                        |
                          system/ogg.dll (esta DLL)  <-- o jogo carrega |
                          intercepta a leitura, decripta na memoria     |
                          com a MESMA chave, e entrega os bytes prontos  v
                                                            o jogo lê normalmente
```

- Nossa `ogg.dll` **reexporta** todas as 43 funções de áudio para a `ogg_real.dll`
  (a libogg original renomeada), então o som continua funcionando.
- Ela faz **IAT hook** de `CreateFileW`/`CreateFileA`. Quando o jogo abre um
  arquivo alvo que começa com o header `Lineage2Ver413`, a DLL lê, decripta e
  devolve um handle para uma cópia temporária já decifrada (apagada ao fechar).

---

## Pré-requisitos

- **Visual Studio 2022** (Community serve) com a carga de trabalho
  **"Desenvolvimento para desktop com C++"**.
- Você tem a `ogg.dll` original do seu client (a libogg verdadeira).

---

## Passo 1 — Configure a SUA chave

Abra `src/config.h` e troque a chave (tem que ser **idêntica** à do encryptor
em `src/Blowfish/L2ServerKey.cs`):

```c
#define L2_SERVER_KEY "SUA_FRASE_SECRETA_AQUI"
```

> A mesma frase precisa estar nos dois lados (encryptor e DLL), senão o jogo
> não conseguirá ler os arquivos.

---

## Passo 2 — Compile em 32-bit (x86)

1. Abra `oggproxy.sln` no Visual Studio.
2. Na barra superior, selecione **Release** e **x86** (NÃO use x64 — o L2
   Interlude é 32-bit).
3. Menu **Compilar → Compilar Solução** (Build Solution), ou `Ctrl+Shift+B`.
4. A DLL sai em: `build\Win32\Release\ogg.dll`.

> Se preferir linha de comando (Developer Command Prompt):
> ```
> msbuild oggproxy.sln /p:Configuration=Release /p:Platform=Win32
> ```

---

## Passo 3 — Instale no client

Na pasta `system/` do seu cliente Lineage 2:

1. **Renomeie** a `ogg.dll` original para **`ogg_real.dll`**.
2. **Copie** a nossa `ogg.dll` (recém-compilada) para o `system/`.

Estado final da pasta `system/`:
```
system/
├── ogg.dll        <- NOSSA DLL (a compilada)
├── ogg_real.dll   <- a libogg ORIGINAL, renomeada
└── ... (resto do client)
```

---

## Passo 4 — Gere os arquivos cifrados

Use o encryptor C# (raiz do repositório, projeto `JNukeCrypt`) com a **mesma
chave**. Ele adiciona o header `Lineage2Ver413` e cifra o corpo com Blowfish.
Coloque os `.dat` cifrados no client e abra o jogo.

---

## Teste rápido

1. Cifre um `.dat` com o encryptor (mesma chave).
2. Coloque no `system/` do client (com a DLL instalada).
3. Abra o jogo. Se o conteúdo carregar normalmente, o decrypt on-the-fly está
   funcionando. Se abrir sem a DLL (ou com a chave errada), o jogo NÃO deve
   conseguir ler o arquivo cifrado — é esse o objetivo.

---

## Notas importantes

- **Arquitetura:** a DLL **precisa** ser x86 (32-bit). x64 não carrega no client.
- **Runtime:** o projeto usa runtime estático (`/MT`) para não exigir o
  Visual C++ Redistributable na máquina dos jogadores.
- **Chave secreta:** nunca distribua sua chave nem o `config.h` preenchido.
- **Antivírus:** DLLs que fazem hook de I/O podem gerar falso-positivo em
  alguns antivírus. Como você compila o código você mesmo (e ele está todo
  aqui, auditável), você sabe exatamente o que ele faz.

---

## Limitações conhecidas (leia antes de testar)

O cliente L2 é baseado na Unreal Engine 2, e o carregamento de pacotes pode
vir de módulos como `Core.dll`/`Engine.dll`. Por isso a DLL aplica o hook em
**todos os módulos carregados** que importam `CreateFileW/CreateFileA` via IAT.

Dois cenários podem exigir ajuste (dependem do seu client específico):

1. **Resolução dinâmica:** se a engine obtém `CreateFileW` via
   `GetProcAddress` em runtime (em vez de import estático), o IAT hook não
   pega. Nesse caso é preciso um hook inline (ex.: MinHook/Detours) — me avise
   e adaptamos.
2. **Módulos carregados depois:** se algum módulo relevante é carregado
   **após** a nossa DLL, ele não estará no snapshot inicial. Solução: hookar
   também `LoadLibrary` para reaplicar. Deixei preparado para evoluir se o
   teste mostrar necessidade.

**Como saber se funcionou:** cifre um `.dat` de texto conhecido, rode o jogo
e veja se o conteúdo carrega. Se não carregar, quase sempre é um dos dois
cenários acima — me diga qual arquivo (`.dat`/`.u`/`.utx`) falhou que ajusto
a estratégia de hook.
```
