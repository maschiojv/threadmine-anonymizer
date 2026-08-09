# Emendas à SPEC — onda 5 (quitação dos débitos técnicos)

**Data:** 2026-08-09 · **Status:** implementadas e cobertas por teste neste repo.
**Ação pendente do fundador:** transplantar estas emendas para
`thread-forge/docs/anonimizador/SPEC.md`, que continua sendo o documento normativo.
Não editei a SPEC diretamente para não sujar a árvore de trabalho do `thread-forge`
(há sessões paralelas nela); o conteúdo abaixo está pronto para colar.

---

## §2 — Vault: cifra por passphrase (deixa de ser "MVP1", passa a implementada)

A linha atual diz: *"Cifra por passphrase = MVP1 (fora das ondas 1-2)"*. Substituir por:

**Vault v2 (cifrado, opcional).** `tm-anon init --encrypt` cria o vault com a metade
secreta selada. Layout:

```json
{
  "version": 2,
  "createdAt": "2026-08-09T...Z",
  "kdf": { "algorithm": "PBKDF2WithHmacSHA256", "iterations": 600000, "salt": "<base64 16B>" },
  "cipher": "AES/GCM/NoPadding",
  "nonce": "<base64 12B>",
  "payload": "<base64 do JSON {key, map, collisions} cifrado>"
}
```

- **Cabeçalho em claro é AAD do GCM.** Sem isso um atacante com acesso de escrita
  reescreveria `iterations` para 1 e devolveria o arquivo; com isso a autenticação
  falha antes de qualquer derivação útil.
- **Nonce novo a cada `save()`** — reúso de nonce sob a mesma chave GCM é a única
  falha criptográfica que destrói a confidencialidade de forma total.
- **v1 (texto claro) continua suportado e é o default.** Passar passphrase a um vault
  v1 é **recusado**, não ignorado: ignorar deixaria o usuário acreditando que um
  arquivo desprotegido está protegido.
- **Fonte da passphrase:** `TM_ANON_PASSPHRASE` ou prompt interativo. **Não existe**
  `--passphrase <valor>` — cairia no histórico do shell e na lista de processos.
- **Escolha do KDF, declarada:** PBKDF2 não é memory-hard; Argon2id/scrypt seriam
  melhores, mas nenhum vem no JDK e o jar não pode ganhar dependência. Trade-off
  assumido explicitamente, não varrido para debaixo do tapete.

## §5.7 — Strip: as seções Heap/Isolates têm DUAS grafias

A regra já nomeia "seções Heap/Isolates". Emenda: a classificação não pode assumir a
grafia do HotSpot (cabeçalho pelado + corpo indentado). O GraalVM escreve
`Heap: { … }` e `Isolates: { … }` **delimitadas por chave**, exigindo contagem de
profundidade — sem ela o `}` final sobra como linha não classificada. O bloco de
metadados `Zing thread dump header:` entra na mesma regra (nenhum parser do ThreadMine
o lê). Antes da emenda essas 16 linhas caíam no fail-closed da §5.8: seguro, mas
entregava ao usuário 16 avisos de "não reconheci esta linha" num dump comum, o que
corrói a confiança no aviso quando ele importa de verdade.

## §5-C — NOVO: dialeto `Thread.dump_to_file -format=json` (JDK 21+)

> Maior vazamento estrutural do lado HotSpot. O `threadContainers[].container` imprime
> `toString()` do executor ou `StructuredTaskScope` dono do grupo de threads — **a única
> posição, em qualquer formato suportado, onde uma classe da aplicação se nomeia fora de
> um stack frame**. `blockedOn`, `waitingOn`, `parkBlocker.object` e
> `monitorsOwned[].locks[]` repetem a forma `FQCN@identityHash`.

1. **Detecção:** chaves `threadDump` + `threadContainers` nos primeiros 4KB. Checada
   ANTES do HotSpot texto — o corpo JSON contém frames e nomes que satisfariam as sondas
   do dialeto texto.
2. **Documento parseado e percorrido, não reescrito linha a linha.** Em JSON toda chave
   e todo valor são strings entre aspas; a regra "texto entre aspas é nome de thread"
   acusaria `"threadDump"` e deixaria passar uma classe dentro de `parkBlocker`.
3. **Chaves casadas exaustivamente; chave desconhecida → valor redigido + warning.**
   É a forma estrutural da §5.8: um campo que um JDK futuro adicionar não pode atravessar
   um rewriter que nunca ouviu falar dele.
4. **Regras por campo:** `name` → §5.3; `stack[]` → §5.1 (mesma implementação do dialeto
   texto, o que mantém o token de uma classe idêntico entre dialetos do mesmo vault);
   `blockedOn`/`waitingOn`/`parkBlocker.object`/`monitorsOwned[].locks[]` → §5.4;
   `container`/`parent` → metade `FQCN@hash` pela §5.4 e metade `poolName` (texto escolhido
   por quem chamou `SharedThreadContainer.create`) pela §5.3. `processId`, `time`,
   `runtimeVersion`, `tid`, `state`, `virtual`, `threadCount`, `depth`, `carrier`,
   `owner` → preservados. `<root>` é estrutura, verbatim.
5. **`container` e `parent` reescritos identicamente** — `parent` referencia outro
   container pela string exata; tokens são determinísticos, então o link sobrevive. Um
   `parent` pendurado quebraria a árvore de containers para qualquer consumidor.
6. **DESVIO DELIBERADO DA §5.9:** o marcador **não pode** ser a 1ª linha `# tm-anon v1`
   sem invalidar o JSON, que é a razão de ser do formato. Vai como **1ª chave** do objeto
   raiz: `"tmAnon": "# tm-anon v1"`. A string literal continua encontrável por busca de
   substring. Nenhum comportamento do servidor depende disso: o
   `DetectorDumpAnonimizado` lê só a primeira linha, e o `DetectorFormatoServiceImpl`
   **não tem padrão de JSON** — o ThreadMine não ingere esse dialeto. Consumidor alvo é
   quem precisa mandar o dump para um fornecedor/colega sem vazar.
7. **`verify` ganha caminho JSON estrutural** (mesmas três perguntas: nada identificável
   sobrou, estrutura intacta, volumetria igual), com 6 testes negativos provando que ele
   REPROVA — verificador que não sabe reprovar transforma "não auditado" em selo verde.
8. **Leitor JSON próprio (`format.json.Json`), separado do `core.MiniJson`.** O MiniJson
   segue restrito ao schema do vault (objeto/string/inteiro) e rejeitando o resto como
   corrupção — propriedade da qual o argumento de auditoria do vault depende. O dump JSON
   precisa de arrays, booleanos, nulos e ponto flutuante; afrouxar o MiniJson custaria
   aquela garantia. Dois leitores pequenos, cada um rígido no seu escopo.

## §5-B — `1LKDEADLOCK`: débito aceito, agora com garantia executável

O texto atual aceita perder o anúncio `Deadlock detected !!!` com o argumento de que o
ciclo continua derivável das `3XMTHREADBLOCK` cruzadas. Isso era **prosa**. Emenda: o
argumento passa a ser verificado por teste (`JavacoreDeadlockSurvivalTest`), que
reconstrói o grafo *wait-for* a partir do arquivo MASCARADO e exige o ciclo fechado, a
correlação token-a-token entre `Owned by:` e os cabeçalhos, e os dois monitores distintos.
Se um dia o strip levar junto as `3XMTHREADBLOCK`, o débito deixa de ser aceitável e o
teste avisa.

## §6 — Corpus: 23 → 26 fixtures; "dialetos não-HotSpot" fechado

`zing-c4-jstack.txt`, `graalvm-native-image.txt` e `jcmd-dump-json-jdk25.txt`.
Motivo de fechar Zing/GraalVM (a SPEC os punha fora de escopo): o ThreadMine tem
`ParserZingImpl` e `ParserGraalVMImpl` dedicados e o `DetectorFormatoServiceImpl` roteia
os dois — o usuário desses runtimes **conseguia subir** o dump e **não conseguia**
anonimizá-lo antes. Os corpos são HotSpot-shaped (o `ParserZingImpl` delega ao
`ParserHotSpotCore`), então já passavam pelo rewriter; faltavam só as seções da §5.7.
