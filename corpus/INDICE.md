# Corpus golden — tm-anon

Dumps 100% sintéticos (namespace fictício `com.acme.*`, threads fictícias, zero dado real),
com forma imitada das fixtures reais do ThreadMine (`backend/src/test/resources/dumps/`).
Cada `fixtures/<nome>.txt` tem um `expectations/<nome>.yaml` (schema da SPEC §6) dizendo o que
um `mask` correto DEVE fazer. Global (vale para todos): 1ª linha do output = `# tm-anon v1`;
linha não classificada → `# [tm-anon: redacted]`; endereços `<0x…>` sempre verbatim.

**20 fixtures**, todas verdes em dois testes independentes: `CorpusGoldenTest` (o mask faz o que a
expectation manda) e `CorpusMaskVerifyTest` (o resultado do mask passa no `verify`, com a mesma
allowlist dos dois lados — foi ele que pegou o vazamento de `<FQCN@hash>` do JDK 24+).

Vocabulário de `invariantes`: `determinismo_intra_dump`, `determinismo_inter_dump`,
`deadlock_nomes_consistentes`, `blank_lines_preservadas`, `enderecos_lock_verbatim`,
`sufixo_numerico_preservado`, `marcador_rota_q`, `ordem_linhas_preservada`,
`aceita_sem_header_full_thread_dump`.

| Fixture | O que exercita | Armadilha de design coberta |
|---|---|---|
| `jstack-jdk8-classic.txt` | jstack JDK 8: sem cpu=/elapsed=, frames sem módulo, `JNI global references:` singular, seção Heap (kill -3), Tomcat/http-nio | lexer não pode assumir campos/módulo pós-JDK9; strip da seção Heap multi-linha |
| `jstack-jdk11-smr.txt` | JDK 11: bloco SMR, cpu=/elapsed=, `java.base@11.0.16/`, G1 tail, `Thread-7`, pool custom com sufixo | strip do bloco SMR sem quebrar blank lines; 2 threads de VM sem linha em branco entre elas |
| `jstack-jdk17-synchronizers.txt` | JDK 17 `-l`: `Locked ownable synchronizers` em toda thread, ReentrantLock held×parked | strip do bloco sem engolir a linha em branco delimitadora; correlação held/waiter por endereço verbatim |
| `jstack-jdk21-virtual-threads.txt` | Loom: VT anônima montada, VT `<pinned: synchronized>`, VT sem carrier, VT nomeada, carriers FJP | marcadores Loom byte a byte; `"" #N virtual` sem nada a tokenizar; carrier no marcador é allowlist |
| `jstack-jdk25-full.txt` | JDK 25: `#N [nid]`, allocated=/defined_classes=, nid decimal, `No compile task`, VirtualThread-unblocker, delayScheduler, process reaper, GC tail | reescrita do nome não pode tocar os campos novos do cabeçalho; threads de infra sem stack/estado |
| `jcmd-thread-print.txt` | `jcmd <pid> Thread.print`: preâmbulo `48350:` + corpo idêntico a jstack | preâmbulo do jcmd não pode ser redigido pelo fail-closed nem confundir a detecção nos 4KB |
| `jcmd-dump-text.txt` | `Thread.dump_to_file -format=text`: `#N "nome" ESTADO`, frames 6 espaços com `java.base/`, `#N "" VIRTUAL` | frames sem `at ` e sem parênteses de módulo @; mesmos canônicos ⇒ mesmos tokens dos outros dialetos |
| `jcmd-dump-text-jdk21.txt` | dialeto **real** do JDK 21-23: `#N "nome"` **sem estado**, `virtual` minúsculo como sufixo, frames 6 espaços; nenhuma linha `java.lang.Thread.State:` no arquivo inteiro | cabeçalho sem estado era `redacted` e o arquivo era recusado pelo `FormatDetector` (nenhuma outra regra de detecção pega esse dialeto) |
| `jcmd-dump-text-jdk25.txt` | dialeto **real** do JDK 24+: `#N "nome" [virtual ]ESTADO <Instant>`, frames `    at `, monitores como `<FQCN@identityHash>`, `, owner #N`, `- lock is eliminated` | o conteúdo entre `<>` deixa de ser endereço e passa a carregar **o nome da classe da aplicação** — preservá-lo verbatim (correto p/ endereço) era vazamento |
| `jstack-jdk25-carrying.txt` | carrier montado: `Carrying virtual thread #N` **no lugar** da linha `java.lang.Thread.State:`; VT montada com marcador Loom; cabeçalho `#N [nid]` | bloco de thread sem linha de estado não pode quebrar o lexer; número após `#` é threadId (não nome) ⇒ verbatim |
| `mxbean-visualvm.txt` | ThreadMXBean/VisualVM: `"nome" Id=N ESTADO on Classe@hash owned by "outra" Id=M`, `app//`, `Number of locked synchronizers` | nome citado em `owned by` recebe o MESMO token do cabeçalho; `Classe@hash` → classe tokenizada, @hash verbatim |
| `deadlock-single-cycle.txt` | Deadlock 1 ciclo: bloco completo `Found one Java-level deadlock:` + `===` + `Java stack information` + `Found 1 deadlock.` | nomes entre aspas do bloco = tokens dos cabeçalhos (SPEC §5.5); classe em `(object 0x…, a X)` tokenizada na moldura |
| `deadlock-two-cycles.txt` | 2 ciclos simultâneos: dois blocos + `Found 2 deadlocks.` plural | atribuições não podem se misturar entre blocos; `billing-sched-1`≠`report-render-1` mesmo sufixo, tokens distintos |
| `multi-dump-3x.txt` | 3 jstacks concatenados, mesmas threads evoluindo de estado | determinismo inter-dump: token estável entre os 3 dumps ou a timeline/correlação do servidor morre |
| `edge-inverted-order.txt` | Arquivo com linhas em ordem invertida (header na última linha) | classificação por forma da linha, não por posição; não reordenar output |
| `edge-no-header.txt` | Sem `Full thread dump`, cabeçalhos mínimos (`#N prio= tid= nid=`) | âncora de header é suficiente mas NÃO necessária; recusar bloquearia upload que o ThreadMine aceita |
| `edge-lambda-inner-cglib.txt` | `$$Lambda$123/0x…` (JDK 15-20) e `$$Lambda/0x…` (21+), `Foo$Bar`/`$1`, `lambda$met$0`, CGLIB `$$EnhancerBySpringCGLIB$$hash` + `(<generated>)`, `<init>`/`<clinit>`, LambdaForm | molduras de classe gerada intactas, só a classe base/método tokenizados (SPEC §5.2); spring = recommended tier |
| `edge-thread-names-route-uuid.txt` | Threads nomeadas por rota c/ query (`sync-/api/orders?id=…`), UUID, hex≥16 + espaços, sufixo `#4`, `Thread-7` | heurística de rota ANTES da regra de sufixo (UUID não pode ser fatiado); token único `t…/q`; allowlist vence heurística |
| `edge-pool-starvation.txt` | Starvation real: `pgto-worker-1..8` todos BLOCKED no mesmo monitor, dono em IO; http-nio ociosos de contraste | prefixo comum ⇒ mesmo token base + sufixos: preserva agrupamento de pool e a detecção de starvation no servidor |
| `edge-relock-compiling.txt` | `waiting to re-lock in wait()`, `<no object reference available>`, `Compiling: com.acme…` (com e sem `%` OSR), `process reaper (pid 4242)`, `gc-notifier-1` | strip do Compiling (vaza FQCN::método fora do formato de frame); sentinela verbatim; `gc-` minúsculo ≠ prefixo infra `GC ` |

## Lacunas — status

- ~~**Linha `Carrying virtual thread #N`**~~ **FECHADA (onda 3I)** — `jstack-jdk25-carrying.txt`,
  duas ocorrências pinadas como âncora. Decisão (SPEC §5.6, não §5.7): **preservar byte a byte**.
  O `#N` é o *threadId* da VT montada, não um nome — não há o que tokenizar, e a linha é lida pelo
  `ParserHotSpotCore.CARRYING_VIRTUAL` do ThreadMine e listada como `structuralMarker` na
  allowlist v1. Detalhe do formato real que a fixture registra: a linha **substitui** a
  `java.lang.Thread.State:` do carrier (o HotSpot imprime uma OU outra), então existe bloco de
  thread legítimo sem linha de estado.
- ~~**Containers no `Thread.dump_to_file -format=text`**~~ **PREMISSA ERRADA — não existem.**
  Verificado contra a fonte do OpenJDK (`jdk/internal/vm/ThreadDumper.java`, tags `jdk-21+35` e
  `master`): o walker do texto é
  `container.threads().forEach(...); container.children().forEach(...)` — ele **percorre** os
  containers mas **não imprime** nenhuma linha de container. `<root>` e
  `java.util.concurrent.ThreadPerTaskExecutor@…` só aparecem no `-format=json`, que está fora da
  SPEC. Nada a implementar; fixture de container seria ficção. O que o dialeto texto REALMENTE
  tinha de não coberto virou `jcmd-dump-text-jdk21.txt` e `jcmd-dump-text-jdk25.txt`.
- **Dialetos não-HotSpot** (OpenJ9, Zing, GraalVM/Isolates) fora do escopo do MVP (SPEC §6 é só HotSpot).
- **JSON format** do `Thread.dump_to_file -format=json` não coberto (formato de saída ≠ text, fora
  da SPEC) — é o único formato onde vivem os containers, e onde o `toString()` de um
  `StructuredTaskScope` da aplicação vazaria FQCN. Candidato natural a uma onda futura.
- **`jcmd-dump-text.txt` (a fixture original) usa uma forma sintética**: `#N "nome" VIRTUAL ESTADO`,
  com `VIRTUAL` maiúsculo e antes do estado. O JDK real nunca imprimiu assim (21-23: sem estado,
  sufixo ` virtual`; 24+: `virtual ` minúsculo + estado + `Instant`). Mantida como está — o mask
  aceita as três formas e o regex do ThreadMine (`THREAD_HEADER_JCMD`) casa a dela — mas quem for
  usá-la como referência de formato deve preferir as duas fixtures novas.
- Expectations citam entradas de allowlist pelo comportamento esperado (http-nio, FJP, Thread-N,
  process reaper…); a fonte de verdade é o artefato da sessão 1B — se a allowlist-v1 divergir,
  ajustar os YAMLs, não o contrário.
