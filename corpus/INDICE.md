# Corpus golden — tm-anon

Dumps 100% sintéticos (namespace fictício `com.acme.*`, threads fictícias, zero dado real),
com forma imitada das fixtures reais do ThreadMine (`backend/src/test/resources/dumps/`).
Cada `fixtures/<nome>.txt` tem um `expectations/<nome>.yaml` (schema da SPEC §6) dizendo o que
um `mask` correto DEVE fazer. Global (vale para todos): 1ª linha do output = `# tm-anon v1`;
linha não classificada → `# [tm-anon: redacted]`; endereços `<0x…>` sempre verbatim.

**23 fixtures**: as 20 HotSpot verdes em dois testes independentes: `CorpusGoldenTest` (o mask faz
o que a expectation manda) e `CorpusMaskVerifyTest` (o resultado do mask passa no `verify`, com a
mesma allowlist dos dois lados — foi ele que pegou o vazamento de `<FQCN@hash>` do JDK 24+); e
**3 OpenJ9 javacore** (`formato: openj9-javacore`, contrato SPEC §5-B) que são o golden set da
o suporte a javacore — ainda SEM implementação que as consuma.

Vocabulário de `invariantes`: `determinismo_intra_dump`, `determinismo_inter_dump`,
`deadlock_nomes_consistentes`, `blank_lines_preservadas`, `enderecos_lock_verbatim`,
`sufixo_numerico_preservado`, `marcador_rota_q`, `ordem_linhas_preservada`,
`aceita_sem_header_full_thread_dump`; javacore (§5-B): `ids_nativos_verbatim`,
`ordem_threadinfo_stacktrace_preservada`, `frames_com_barra_tokenizados`,
`blocked_on_consistente`, `verify_exit4_se_secao_proibida_sobrevive`,
`verify_exit4_se_1tifilename_com_conteudo`. Expectations javacore têm campos extras:
`ancoras_deteccao_4kb`, `secoes_preservadas`, `secoes_stripadas`, `linhas_redigidas`.

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
| `openj9-javacore-classic.txt` | Javacore IBM clássico (J2RE 1.4.2, como o real do ThreadMine): sem `1XMJAVAVERSION`, threads `state:R/CW/B` com `TID/sys_thread_t/native ID` na linha, `1TIFILENAME` com path local, `1CICMDLINE` com `-D` de senha/host, `1CISYSCP` gigante, LK com monitores `classe@endereço` + nomes de thread, CL com classloaders/classes | superfície-monstro do §3 da AVALIACAO inteira num arquivo: strip por seção (CI/DC/DG/ST/XE/LK/CL + XHPI/End por fail-closed §5-B.6); `1TISIGINFO` é a ÚNICA âncora nos 4KB; pool clássico `X: 'N' for queue: 'Q'` não tem sufixo `-N` ⇒ 1 token por thread (agrupamento de pool se perde — limitação registrada); thread sem stack não quebra o lexer |
| `openj9-javacore-moderno.txt` | OpenJ9 0.41 em container: seções `ENVINFO/LOCKS/THREADS/CLASSES` (mesmas famílias CI/LK/XM/CL), `1XMJAVAVERSION`, `3XMTHREADINFO3 Java.lang.Thread.State:`, `3XMTHREADBLOCK Blocked on: … Owned by: "…"`, frames com **barra** + `(Compiled Code)`, pool `pgto-worker-N`, thread de rota com `?` e espaços, `2CIENVVAR` com `HOSTNAME`/senha, `Anonymous native thread`, `4XENATIVESTACK` | nomes de seção modernos ≠ clássicos (identificação por família de token, não pelo texto do `0SECTION`); `com/acme/...` deve normalizar p/ o MESMO token do canônico pontilhado (e `java/util/...` continua allowlist); nome citado em `Owned by:` = token do cabeçalho; linhas sem regra (nativas) caem no fail-closed sem derrubar o arquivo |
| `openj9-javacore-deadlock.txt` | Deadlock OpenJ9: `1LKDEADLOCK`/`2LKDEADLOCKTHR`/`4LKDEADLOCKOBJ` + monitores com `3LKWAITERQ/3LKWAITER` dentro de LOCKS, e as duas threads `state:B` com `3XMTHREADBLOCK` cruzadas no THREADS | o strip integral do LOCKS (§5-B.2) apaga o anúncio "Deadlock detected !!!" — a evidência sobrevivente é o ciclo fechado das `3XMTHREADBLOCK`, que TEM que continuar fechado após o mask (mesmos tokens de thread/classe nos dois lados); `verify` exit 4 se qualquer linha `*LKDEADLOCK*` sobreviver |
| `zing-c4-jstack.txt` | Azul Zing (Prime): banner `Full thread dump Zing (…)`, bloco `Zing thread dump header:` com metadados, threads do coletor C4 | o banner é a âncora de detecção de formato — reescrevê-lo faria o dump ser classificado como outro dialeto; o bloco de metadados não é lido por analisador nenhum e caía inteiro no fail-closed (vira strip); threads `C4 …` já eram allowlist (regex de GC) |
| `graalvm-native-image.txt` | GraalVM Native Image: estado **inline** no cabeçalho, `tid=` decimal, sem linha `java.lang.Thread.State:`, blocos `Heap: { … }` e `Isolates: { … }` delimitados por chave | `Isolates` é o ÚNICO lugar do corpus **texto** onde uma classe da aplicação aparece fora de um frame (`Object at 0x…: com.acme.boot.ServiceRegistry`) — a §5.7 manda stripar a seção, e a delimitação por chave (não por indentação) exige contar profundidade, senão o `}` final vaza como linha não classificada |
| `jcmd-dump-json-jdk25.txt` | `jcmd Thread.dump_to_file -format=json` (JDK 21+), **derivada de captura real** de um processo JDK 25 (pool de plataforma, virtual threads, lock contendido, thread de rota): `threadContainers` com `parent`/`owner`, `parkBlocker` como OBJETO, `monitorsOwned[].locks[]`, `depth` numérico, `virtual` booleano | `container` carrega `toString()` do executor/StructuredTaskScope — a classe da aplicação se nomeando fora de qualquer frame; `parent` referencia outro container pela string exata (link pendura se as duas não forem reescritas igual); o marcador da §5.9 **não pode** ser 1ª linha `#` sem invalidar o JSON (vai como 1ª chave); chave desconhecida de um JDK futuro → redigida, não repassada |

## Lacunas — status

- ~~**Linha `Carrying virtual thread #N`**~~ **FECHADA** — `jstack-jdk25-carrying.txt`,
  duas ocorrências pinadas como âncora. Decisão (SPEC §5.6, não §5.7): **preservar byte a byte**.
  O `#N` é o *threadId* da VT montada, não um nome — não há o que tokenizar, e a linha é lida pelo
  lida pelo parser HotSpot do ThreadMine e listada como `structuralMarker` na
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
- ~~**Dialetos não-HotSpot**~~ **FECHADA.** OpenJ9 javacore: 3 fixtures `openj9-javacore-*`.
  **Zing e GraalVM:** `zing-c4-jstack.txt` e `graalvm-native-image.txt`. Os dois corpos são
  HotSpot-shaped (o Zing é derivado do HotSpot e seu `jstack` imprime o mesmo layout), então já
  passavam pelo rewriter HotSpot; o que faltava eram as seções: blocos `Heap: { }` / `Isolates:
  { }` no estilo do GraalVM (delimitados por chave, não por indentação) e o cabeçalho de
  metadados do Zing. Eram 16 linhas caindo em `redacted` — seguro, mas entregava ao usuário 16
  avisos de "não reconheci esta linha" num dump perfeitamente comum, o que corrói a confiança no
  aviso quando ele importa. Agora são `stripped`, com 0 redações nas duas fixtures.
- **GraalVM Native Image — cabeçalho mínimo sem `#N`/`prio=`:** o formato admite, em tese, um
  cabeçalho `"nome" tid=1 nid=0x1 runnable` com todos os campos opcionais ausentes, que o
  `QUOTED_HEADER` do rewriter não casa (fail-closed → a thread inteira vira `redacted`). Não
  reproduzido em dump real e não coberto por fixture: registrado aqui em vez de "corrigido" com
  base em suposição.
- **Notas de formato do javacore (decisões tomadas ao construir o corpus — ler antes de implementar a o suporte a javacore):**
  1. **`1XMJAVAVERSION` e `3XMTHREADINFO3 Java.lang.Thread.State:` são dialeto do PARSER do
     ThreadMine, não do OpenJ9 real.** Javacore de verdade tem a versão em `1CIJAVAVERSION`
     (seção ENVINFO/CI — que a §5-B manda stripar) e usa `3XMTHREADINFO3` como cabeçalho
     `Java callstack:`; o estado real vive no `state:X` da própria `3XMTHREADINFO`. As fixtures
     modernas incluem os dois tokens do parser (o golden set serve à paridade com o ThreadMine),
     mas o mask precisa aceitar javacores SEM eles. **Emenda IMPLEMENTADA (fix-javacore-version):**
     ao stripar a CI/ENVINFO, o payload da `1CIJAVAVERSION` é re-emitido uma única vez logo após
     o marcador de strip, sob o token `1XMJAVAVERSION` (o único que o parser OpenJ9 lê;
     re-emitir o token `1CI` seria flagado pelo `verify` como seção proibida sobrevivente).
     Payload verbatim atrás de filtro fail-closed por palavra: vocabulário de versão passa;
     fragmento com cara de path/env/hostname vira `[tm-anon:redacted]` (sem dígitos, para nunca
     ser lido como versão) com warning. Sem re-emissão quando o dump já tem `1XMJAVAVERSION`.
  2. **Nomes de `0SECTION` mudam entre gerações** (clássico: `CI/LK/XM/CL`; moderno:
     `ENVINFO/LOCKS/THREADS/CLASSES`). A §5-B nomeia seções pela família de token — a
     identificação DEVE ser pela família (prefixo alfabético do token de coluna 0), nunca pelo
     texto do `0SECTION`, senão o fail-closed §5-B.6 stripa a seção THREADS inteira de um
     javacore moderno.
  3. **Frames modernos usam barra** (`com/acme/...`) e admitem `(Compiled Code)` dentro do
     parêntese `(Arquivo.java:NN(Compiled Code))` — a §5.1 (escrita para FQCN com ponto) precisa
     de normalização barra→ponto antes de allowlist/canônico, inclusive para RECONHECER
     `java/util/...` como allowlist. No dialeto **clássico** a mesma moldura vem SEM número de
     linha (`(Arquivo.java(Compiled Code))`): o `mask` tokeniza o arquivo e preserva a moldura,
     e o `verify` precisa recortá-la antes de exigir token do nome do arquivo — sem isso, um
     javacore real bem mascarado sai com exit 4 (falso positivo, mesma família do `(<generated>)`
     do CGLIB). Pinado pelo invariante `moldura_compiled_code_preservada` do fixture clássico.
  4. **Strip do LOCKS apaga a declaração explícita de deadlock** (`1LKDEADLOCK`). Custo aceito
     pela §5-B (o parser OpenJ9 ignora LK); a detecção sobrevive pelas `3XMTHREADBLOCK`
     cruzadas — pinado pela fixture de deadlock.
  5. Linhas sem regra dentro do XM/THREADS (`Anonymous native thread` sem aspas,
     `4XENATIVESTACK`, `3XMJAVALTHREAD`/`3XMTHREADINFO1`/`3XMCPUTIME`) — as três últimas são
     metadados neutros preserváveis, mas a §5-B não as cita; as expectations tratam só as duas
     primeiras como fail-closed e deixam as demais como decisão (preservar é seguro:
     não carregam identificador de app).
  6. **Allowlist v2 (candidatos OpenJ9):** `JIT Compilation Thread-`, `IProfiler`,
     `Attach API wait loop`, marcador estrutural p/ `Anonymous native thread`. Hoje as
     expectations declaram esses nomes como tokenizados (allowlist-v1 não os cobre).
- ~~**JSON format** do `Thread.dump_to_file -format=json`~~ **FECHADA.** O vazamento previsto era
  real: o `threadContainers[].container` imprime o `toString()` do executor ou
  `StructuredTaskScope` dono do grupo (`com.acme.batch.LedgerScope@4f2b1a`) — a classe da
  aplicação se nomeando fora de qualquer frame — e `blockedOn`/`waitingOn`/`parkBlocker.object`/
  `monitorsOwned[].locks[]` repetem a forma. Antes disso o `mask` **recusava** o arquivo (exit 2:
  fail-closed correto, mas quem tinha o dump ficava sem saída). Agora: fixture
  `jcmd-dump-json-jdk25.txt` (captura real de JDK 25), `format.json.JsonThreadDumpRewriter`
  (documento parseado e percorrido, chave desconhecida → redigida) e caminho JSON no `verify`.
  Desvio deliberado: o marcador vai como 1ª **chave** (`"tmAnon"`), não como 1ª linha `#`, que
  invalidaria o JSON.
- **`jcmd-dump-text.txt` (a fixture original) usa uma forma sintética**: `#N "nome" VIRTUAL ESTADO`,
  com `VIRTUAL` maiúsculo e antes do estado. O JDK real nunca imprimiu assim (21-23: sem estado,
  sufixo ` virtual`; 24+: `virtual ` minúsculo + estado + `Instant`). Mantida como está — o mask
  aceita as três formas e o regex do ThreadMine (`THREAD_HEADER_JCMD`) casa a dela — mas quem for
  usá-la como referência de formato deve preferir as duas fixtures novas.
- Expectations citam entradas de allowlist pelo comportamento esperado (http-nio, FJP, Thread-N,
  process reaper…); a fonte de verdade é o artefato da quem gerou a allowlist — se a allowlist-v1 divergir,
  ajustar os YAMLs, não o contrário.
