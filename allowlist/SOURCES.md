# SOURCES — origem de cada entrada `required` da allowlist v1

**Artefato:** [allowlist-v1.json](allowlist-v1.json) · **Repo:** `thread-forge` · **Commit:** `3a50432be6b6fc632409f3e2a8cabd6adf7d14b6` · **Data:** 2026-07-24
**Contratos:** [SPEC.md §3](../SPEC.md) (schema) · [AVALIACAO_ANONIMIZADOR_LOCAL.md §1](../../AVALIACAO_ANONIMIZADOR_LOCAL.md) (por que cada coisa importa)

Todas as linhas foram **verificadas no código atual** neste commit (as linhas do enunciado da tarefa eram referência; onde divergiram, vale o que está aqui). Paths relativos à raiz do repo; abaixo abreviados assim:

| Abrev. | Path |
|---|---|
| `PadroesDeteccao.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/detector/PadroesDeteccao.java` |
| `ParserHotSpotCore.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/ParserHotSpotCore.java` |
| `DetectorThreadOrfa.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/detector/DetectorThreadOrfa.java` |
| `CatalogoRecomendacaoAcao.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/CatalogoRecomendacaoAcao.java` |
| `RenderizadorPrompt.java` | `backend/src/main/java/com/alliah/threadforge/admin/prompts/service/impl/RenderizadorPrompt.java` |
| `HeuristicaInteressante.java` | `backend/src/main/java/com/alliah/threadforge/analise/timeline/service/impl/calc/HeuristicaInteressante.java` |
| `DetectorFormatoServiceImpl.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/DetectorFormatoServiceImpl.java` |
| `ContencaoCalc.java` | `backend/src/main/java/com/alliah/threadforge/analise/comparacao/service/impl/diff/ContencaoCalc.java` |
| `DetectorThreadLeak.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/detector/DetectorThreadLeak.java` |
| `DetectorLockContention.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/detector/DetectorLockContention.java` |
| `DetectorDeadlock.java` | `backend/src/main/java/com/alliah/threadforge/analise/service/impl/detector/DetectorDeadlock.java` |

**Semântica de match no servidor** (o tm-anon precisa reproduzir para ter paridade):

- Frames: `stackContemPadrao` usa **`contains()`** (`PadroesDeteccao.java:369-372`); `ehFrameDeNegocio` usa **`startsWith()`** sobre a linha *strip*ada (`:351-354`).
- Nomes de thread: `ehThreadInternaJvm` usa **`startsWith()`** + **`endsWith()`** (`:171-178`); pools HTTP usam **`matches()`** (`:362-367`).
- **Não existe nenhum match por igualdade de nome de thread em nenhuma das 8 fontes** — por isso `threadNameExact` está vazio (mantido só por fidelidade ao schema da SPEC §3). Toda entrada de nome vive em `threadNamePrefixes`, `threadNameSuffixes` ou `threadNameRegexes`.

---

## 1. `required.packagePrefixes` (30 entradas)

Consolidados com **longest-prefix match**. Como o servidor casa frames por `contains()`/`startsWith()`, o prefixo mais **largo** de cada família é o que garante paridade — entradas mais específicas do código (ex.: `org.apache.tomcat.`) ficam **subsumidas** e estão anotadas na coluna de origem para rastreabilidade.

| # | Prefixo | Origem (arquivo:linha) |
|---|---|---|
| 1 | `java.` | `PadroesDeteccao.java:252` (PREFIXOS_FRAMES_INFRA) · `DetectorThreadOrfa.java:88` · `CatalogoRecomendacaoAcao.java:586` · `RenderizadorPrompt.java:66` · subsume `PadroesDeteccao.java:27-29` (PADROES_IO), `:34,36` (PADROES_REDE), `:41` (PADROES_DB), `:51-53` (PADROES_QUERY_EM_EXECUCAO), `:73` (PADROES_HTTP_CLIENT), `:186,189-192,195,197-198,201,203` (PADROES_QUEUE_IDLE), `:236-237` (PADROES_IO_IDLE) |
| 2 | `javax.` | `PadroesDeteccao.java:252` · `DetectorThreadOrfa.java:89` · `CatalogoRecomendacaoAcao.java:587` · `RenderizadorPrompt.java:66` · subsume `PadroesDeteccao.java:41` (`javax.sql.`), `:91` (`javax.jms.`) |
| 3 | `jakarta.` | `PadroesDeteccao.java:252` · `DetectorThreadOrfa.java:90` · `RenderizadorPrompt.java:66` · subsume `PadroesDeteccao.java:91` (`jakarta.jms.`) |
| 4 | `jdk.` | `PadroesDeteccao.java:252` · `DetectorThreadOrfa.java:91` · `CatalogoRecomendacaoAcao.java:588` · `RenderizadorPrompt.java:66` · subsume `PadroesDeteccao.java:74` (`jdk.internal.net.http`), `:201` (`jdk.internal.ref.CleanerImpl`) |
| 5 | `sun.` | `PadroesDeteccao.java:252` · `DetectorThreadOrfa.java:92` · `CatalogoRecomendacaoAcao.java:589` · `RenderizadorPrompt.java:66` · subsume `PadroesDeteccao.java:28,34` (`sun.nio.ch.`), `:225-235` (PADROES_IO_IDLE, todos os selectors) |
| 6 | `com.sun.` | `PadroesDeteccao.java:252` · `CatalogoRecomendacaoAcao.java:590` · `RenderizadorPrompt.java:66` |
| 7 | `org.apache.` | `DetectorThreadOrfa.java:94` · `RenderizadorPrompt.java:67` · subsume `PadroesDeteccao.java:253` (`org.apache.tomcat.`/`.catalina.`/`.coyote.`), `:35` (`org.apache.http`), `:43` (`org.apache.commons.dbcp`), `:71-72` (`org.apache.http.impl.client`, `org.apache.hc.client5`), `:81` (`org.apache.kafka.clients.consumer`), `:93` (`org.apache.activemq`, `org.apache.qpid`), `:187,193` (Tomcat ThreadPoolExecutor/TaskQueue), `CatalogoRecomendacaoAcao.java:591-592` |
| 8 | `org.eclipse.` | `RenderizadorPrompt.java:67` · subsume `PadroesDeteccao.java:254` (`org.eclipse.jetty.`) |
| 9 | `org.springframework.` | `PadroesDeteccao.java:257` · `DetectorThreadOrfa.java:93` · `CatalogoRecomendacaoAcao.java:593` · `RenderizadorPrompt.java:67` · subsume `PadroesDeteccao.java:65-66` (RestTemplate/WebClient), `:82` (kafka.listener), `:87` (amqp.rabbit.listener), `:92` (jms.listener), `:113-115` (scheduling) |
| 10 | `org.quartz.` | `PadroesDeteccao.java:258` · subsume `:116-118` (PADROES_SCHEDULER) |
| 11 | `org.hibernate.` | `DetectorThreadOrfa.java:95` |
| 12 | `org.jboss.` | `PadroesDeteccao.java:255` · `RenderizadorPrompt.java:68` · subsume `PadroesDeteccao.java:205-206` (`org.jboss.threads.EnhancedQueueExecutor`) |
| 13 | `org.wildfly.` | `PadroesDeteccao.java:255` |
| 14 | `org.xnio.` | `PadroesDeteccao.java:254` · subsume `:244` (`org.xnio.nio.WorkerThread.run`) |
| 15 | `io.undertow.` | `PadroesDeteccao.java:254` · `RenderizadorPrompt.java:68` |
| 16 | `io.netty.` | `PadroesDeteccao.java:256` · `DetectorThreadOrfa.java:96` · `RenderizadorPrompt.java:67` · subsume `PadroesDeteccao.java:240-242` (epoll/kqueue/NioEventLoop) |
| 17 | `io.grpc.` | `PadroesDeteccao.java:238-239` e `:304-305` — comentários normativos: o matcher usa `contains()` **de propósito** para cobrir Netty *shaded* (`io.grpc.netty.shaded.io.netty.channel.epoll.Native.epollWait`). Tokenizar `io.grpc.` quebraria o `contains()` e um I/O worker ocioso passaria a parecer ocupado |
| 18 | `reactor.` | `PadroesDeteccao.java:256` · `DetectorThreadOrfa.java:97` |
| 19 | `kotlin.` | `PadroesDeteccao.java:258` · `RenderizadorPrompt.java:68` |
| 20 | `scala.` | `PadroesDeteccao.java:258` · `RenderizadorPrompt.java:68` |
| 21 | `okhttp3.` | `PadroesDeteccao.java:35` (PADROES_REDE) · `:67-68` (PADROES_HTTP_CLIENT) |
| 22 | `feign.` | `PadroesDeteccao.java:69-70` (PADROES_HTTP_CLIENT) |
| 23 | `org.postgresql.` | `PadroesDeteccao.java:42` (PADROES_DB) · `:54-55` (PADROES_QUERY_EM_EXECUCAO) |
| 24 | `com.mysql.` | `PadroesDeteccao.java:42` · `:56-57` |
| 25 | `oracle.jdbc.` | `PadroesDeteccao.java:42` · `:58-59` |
| 26 | `com.zaxxer.hikari.` | `PadroesDeteccao.java:43` (no código sem ponto final: `"com.zaxxer.hikari"`) |
| 27 | `com.mchange.v2.c3p0.` | `PadroesDeteccao.java:44` (no código sem ponto final) |
| 28 | `com.rabbitmq.` | `PadroesDeteccao.java:86` (PADROES_CONSUMER_RABBIT) |
| 29 | `com.amazonaws.` | `PadroesDeteccao.java:97` (PADROES_CONSUMER_SQS) |
| 30 | `software.amazon.awssdk.` | `PadroesDeteccao.java:98` (PADROES_CONSUMER_SQS) |

### Fragmentos de frame sem pacote (PADROES_CONSUMER_IDLE) — cobertos, mas por tabela

`PadroesDeteccao.java:103-109` casa fragmentos **sem pacote**: `KafkaConsumer.poll`, `Consumer.receive`, `MessageConsumer.receive`, `Channel.basicConsume`, `ReceiveMessage`. Não cabem em `packagePrefixes` (não são prefixos de pacote), mas as classes reais que os produzem estão todas sob prefixos já required (`org.apache.kafka.` → #7, `javax.jms.`/`jakarta.jms.` → #2/#3, `com.rabbitmq.` → #28, `com.amazonaws.`/`software.amazon.awssdk.` → #29/#30), então **o `contains()` continua casando** depois da máscara. O desvio residual é o descrito na AVALIACAO §1.2 item 9a: frames **do app** que hoje casam esses fragmentos *acidentalmente* (ex.: uma classe própria chamada `Consumer.receive`) deixam de casar — mudança benigna (remove falso positivo) e documentada, não corrigida.

---

## 2. `required.threadNameExact` (0 entradas)

Vazio por construção. Nenhuma das 8 fontes compara nome de thread por igualdade — todas usam `startsWith` (`PadroesDeteccao.java:172-173`, `HeuristicaInteressante.java:53-55`), `endsWith` (`PadroesDeteccao.java:177`) ou `matches`/`find` de regex. Nomes completos como `Reference Handler` entram em `threadNamePrefixes` (§3) porque é assim que o servidor os trata; rebaixá-los a match exato criaria divergência de detecção em nomes como `Reference Handler-2`.

---

## 3. `required.threadNamePrefixes` (44 entradas)

Semântica: `nome.startsWith(entrada)` → preservar o nome **inteiro** verbatim.

### 3.1 De `PadroesDeteccao.PREFIXOS_THREADS_INTERNAS` (`:141-163`)

| # | Prefixo | Linha |
|---|---|---|
| 1 | `Reference Handler` | `PadroesDeteccao.java:143` |
| 2 | `Finalizer` | `:143` |
| 3 | `Signal Dispatcher` | `:143` |
| 4 | `Attach Listener` | `:143` |
| 5 | `Common-Cleaner` | `:144` |
| 6 | `Cleaner-` | `:144` |
| 7 | `Notification Thread` | `:145` |
| 8 | `Service Thread` | `:145` |
| 9 | `Monitor Deflation Thread` | `:145` |
| 10 | `C1 CompilerThread` | `:146` |
| 11 | `C2 CompilerThread` | `:146` |
| 12 | `GC ` | `:147` |
| 13 | `G1 ` | `:147` |
| 14 | `ZGC ` | `:147` |
| 15 | `Shenandoah ` | `:147` |
| 16 | `VM Thread` | `:148` |
| 17 | `VM Periodic Task Thread` | `:148` |
| 18 | `DestroyJavaVM` | `:149` |
| 19 | `Jndi-Dns-` | `:149` |
| 20 | `VirtualThread-unblocker` | `:150` |
| 21 | `Read-Poller` | `:150` |
| 22 | `Write-Poller` | `:150` |
| 23 | `Timer` | `:152` |
| 24 | `TimerQueue` | `:152` (subsumido por `Timer`; mantido por rastreabilidade) |
| 25 | `Catalina-utility-` | `:154` |
| 26 | `parallel-` | `:156` |
| 27 | `reactor-http-nio-` | `:158` |
| 28 | `reactor-tcp-nio-` | `:158` |
| 29 | `MSC service thread` | `:160` |
| 30 | `Reference Reaper` | `:160` |
| 31 | `ServerService Thread Pool` | `:160` |
| 32 | `Periodic Recovery` | `:161` |
| 33 | `Transaction Reaper` | `:161` |
| 34 | `Transaction Expired Entry Monitor` | `:161` |
| 35 | `IdleRemover` | `:162` |
| 36 | `ConnectionValidator` | `:162` |
| 37 | `DeploymentScanner-threads` | `:162` |

### 3.2 De `HeuristicaInteressante.PREFIXOS_INTERNAS_JVM` (`:23-29`) — lista **paralela**, não idêntica

Todos os itens dessa lista já constam acima, **exceto** dois, que são **mais largos** que os equivalentes de `PadroesDeteccao` e por isso entram como entradas próprias (a allowlist é a UNIÃO; o prefixo mais curto vence):

| # | Prefixo | Linha | Nota |
|---|---|---|---|
| 38 | `GC Thread` | `HeuristicaInteressante.java:26` | já coberto por `GC ` (#12); mantido por rastreabilidade |
| 39 | `VM Periodic Task` | `HeuristicaInteressante.java:28` | **mais largo** que `VM Periodic Task Thread` (#17) de `PadroesDeteccao.java:148` |

Confirmações de origem duplicada (mesma string nas duas listas): `Reference Handler`, `Finalizer`, `Common-Cleaner`, `Cleaner-` (`:24`); `Service Thread`, `Signal Dispatcher`, `Notification Thread` (`:25`); `Monitor Deflation Thread`, `DestroyJavaVM` (`:26`); `Jndi-Dns-`, `VirtualThread-unblocker`, `Read-Poller`, `Write-Poller` (`:27`); `Catalina-utility-`, `parallel-`, `Attach Listener`, `VM Thread` (`:28`).

### 3.3 De `PadroesDeteccao.PREFIXOS_SCHEDULER` (`:122-128`)

| # | Prefixo | Linha |
|---|---|---|
| 40 | `scheduling-` | `PadroesDeteccao.java:123` |
| 41 | `TaskScheduler-` | `:124` |
| 42 | `ThreadPoolTaskScheduler-` | `:125` |
| 43 | `QuartzScheduler_` | `:126` |
| 44 | `DefaultQuartzScheduler` | `:127` |

---

## 4. `required.threadNameSuffixes` (3 entradas)

Semântica: `nome.endsWith(entrada)` (`PadroesDeteccao.java:177`) → preservar o nome inteiro verbatim.

| # | Sufixo | Origem |
|---|---|---|
| 1 | `-Acceptor` | `PadroesDeteccao.java:168` (SUFIXOS_INFRA_HTTP) |
| 2 | `-Poller` | `:168` |
| 3 | `-ClientPoller` | `:168` |

---

## 5. `required.threadNameRegexes` (11 entradas)

Semântica: match (âncoras explícitas nos próprios padrões) → preservar o nome inteiro verbatim. Onde a constante Java usa `Pattern.CASE_INSENSITIVE`, a flag foi **materializada como `(?i)` inline** para que um consumidor que aplique a regex crua tenha a mesma semântica.

| # | Regex | Origem | Detectores que morrem se tokenizar |
|---|---|---|---|
| 1 | `^http-nio-\d+-exec-\d+$` | `PadroesDeteccao.java:17` (POOL_HTTP_TOMCAT) | PoolExaurido, RequisicaoPresa |
| 2 | `^qtp\d+-\d+$` | `:18` (POOL_HTTP_JETTY) | idem |
| 3 | `^XNIO-\d+-task-\d+$` | `:19` (POOL_HTTP_UNDERTOW) | idem |
| 4 | `^default-task-\d+$` | `:20` (POOL_HTTP_DEFAULT) | idem |
| 5 | `^Thread-\d+$` | `:132` (THREAD_BARE_NAME) · `DetectorThreadLeak.java:42` (THREAD_SEM_POOL — cópia local idêntica) | ThreadOrfa, ThreadLeak (cheque 1) |
| 6 | `^(default\|XNIO-\d+) (I/O\|Accept)(-\d+)?$` | `:288-289` (XNIO_IO_WORKER) | fallback de I/O idle sem stack (`:318`) |
| 7 | `(?i)^(GC \|G1 \|C4 \|ZGC \|Shenandoah \|Concurrent Mark\|ParallelGC)` | `ParserHotSpotCore.java:110-111` (GC_THREAD) | `tipoThread="gc"` (`:459`) — contadores e filtros de UI |
| 8 | `(?i)^(C[12] \|Compiler)` | `ParserHotSpotCore.java:112-113` (COMPILER_THREAD) | `tipoThread="compiler"` (`:460`) |
| 9 | `(?i)^(VM \|Signal \|Finalizer\|Reference Handler\|Attach Listener)` | `ParserHotSpotCore.java:114-115` (VM_THREAD) | `tipoThread="vm"` (`:461`) |
| 10 | `^VirtualThread\[.*` | `ParserHotSpotCore.java:462-463` (`nome.startsWith("VirtualThread[")`) | `tipoThread="virtual"` → DetectorVirtualThreadPinned e MetricasVirtualThread |
| 11 | `^ForkJoinPool-\d+-worker-\d+$` | **sem match direto por nome no código** — exigido por [SPEC.md §3](../SPEC.md) (exemplo do schema) e [AVALIACAO §1.2 item 4](../../AVALIACAO_ANONIMIZADOR_LOCAL.md); é o nome default do **carrier** de virtual threads, chave de `AgrupamentoCarrier` (`ParserHotSpotCore.java:417-453`), e o pool casa `PADROES_QUEUE_IDLE` por frame (`PadroesDeteccao.java:197-198`) | agrupamento por carrier / legibilidade do diagnóstico Loom |

> Entrada #11 é a **única** required que não deriva de um match por nome no código do servidor — está aqui por mandato da SPEC e porque é nome gerado pelo JDK (não é segredo de ninguém). Ver §8.

---

## 6. `required.structuralMarkers` (40 entradas) — literais preservados verbatim

Não são identificadores: são âncoras de formato/estado que o parser e os detectores procuram por texto. Tokenizar qualquer uma delas quebra parse ou detecção.

| Marcador | Origem | Papel |
|---|---|---|
| `Full thread dump` | `DetectorFormatoServiceImpl.java:22` (OPENJDK_PATTERN) · `:18,26,30` · `ParserHotSpotCore.java:99` | âncora de detecção de formato (primeiros 4KB) e de versão |
| `Java HotSpot` | `DetectorFormatoServiceImpl.java:18` | discrimina HOTSPOT |
| `HotSpot` | `ParserHotSpotCore.java:101` (JVM_VENDOR) | vendor |
| `OpenJDK` | `DetectorFormatoServiceImpl.java:18,22` · `ParserHotSpotCore.java:101` | formato + vendor |
| `Zing` | `DetectorFormatoServiceImpl.java:26` · `ParserHotSpotCore.java:101` | formato ZING + vendor |
| `GraalVM` | `DetectorFormatoServiceImpl.java:30` · `ParserHotSpotCore.java:101` | formato GRAALVM + vendor |
| `1TISIGINFO` | `DetectorFormatoServiceImpl.java:34` | âncora OpenJ9 (OPENJDK_IEE) |
| `3XMTHREADINFO` | `:34` | idem |
| `1XMJAVAVERSION` | `:34` | idem |
| `JRE ` | `ParserHotSpotCore.java:98` (JVM_VERSION) | versão da JVM |
| `java version "` | `:98` | versão da JVM |
| `java.lang.Thread.State:` | `ParserHotSpotCore.java:69-70` (THREAD_STATE) | estado da thread — insumo de **todos** os detectores |
| `RUNNABLE` | `:76,83` · `DetectorFormatoServiceImpl.java:41,47` | estado |
| `BLOCKED` | idem | estado |
| `WAITING` | idem | estado |
| `TIMED_WAITING` | idem | estado |
| `NEW` | idem | estado |
| `TERMINATED` | idem | estado |
| `Id=` | `DetectorFormatoServiceImpl.java:41` (THREADMXBEAN_PATTERN) · `ParserHotSpotCore.java:73-76` | âncora do formato ThreadMXBean/VisualVM |
| `daemon` | `ParserHotSpotCore.java:51` (grupo 3 do THREAD_HEADER) | flag do cabeçalho |
| `virtual` | `:52` (grupo 4) | flag Loom (JDK 21+) |
| `prio=` | `:53` | cabeçalho |
| `cpu=` | `:54` | insumo do DetectorCpuBound |
| `elapsed=` | `:55` | cabeçalho |
| `tid=` | `:56` | cabeçalho (chave de lookup na UI) |
| `nid=` | `:57` | cabeçalho |
| `at ` | `:86-87` (STACK_FRAME) | prefixo de frame — sem ele o stack some |
| `- locked <` | `:91-92` (LOCKED) | lock detido |
| `- waiting on` | `:93-94` (WAITING_ON) | lock esperado |
| `- waiting to lock` | `:93-94` | lock esperado |
| `- parking to wait for` | `:93-94` | lock esperado |
| `(a ` | `:92` (grupo 2 do LOCKED) | moldura da classe do objeto lockado (a **classe** dentro é tokenizada) |
| `Found one Java-level deadlock:` | `:213` | gatilho do bloco de deadlock |
| `Found a Java-level deadlock:` | `:214` | gatilho alternativo |
| `===` | `:229` (`linha.startsWith("===")`) | abre **e** fecha o bloco de deadlock |
| `<pinned: synchronized>` | `:65-66` (PINNED_MARKER) | flag `pinned` → DetectorVirtualThreadPinned |
| `<virtual thread is mounted on carrier thread ` | `:61-62` (CARRIER_THREAD) | moldura do carrier (o **nome** dentro é token de thread) |
| `Carrying virtual thread #` | `:63-64` (CARRYING_VIRTUAL) | contrapartida no carrier |
| `no object reference available` | `ContencaoCalc.java:34` (LOCK_SENTINELA_SEM_REFERENCIA) · `DetectorLockContention.java:34` (cópia local) | sentinela de monitor coletado — agrupar por ela juntaria recursos distintos |
| `"` (aspas duplas) | `ParserHotSpotCore.java:49,247` (`linha.startsWith("\"")`) · `DetectorDeadlock.java:23-24` (`"(.+?)"`) | delimitador de nome no cabeçalho **e** no bloco de deadlock |

---

## 7. `required.structuralMarkerRegexes` (19 entradas) — molduras preservadas

Cada regex é uma **moldura**: tudo que não é grupo de captura de identificador do app deve sair verbatim; o conteúdo capturado segue as regras de reescrita da [SPEC §5](../SPEC.md).

| Regex | Origem | Constante |
|---|---|---|
| `^"(.*?)"(\s+#\d+)?(?:\s+(daemon))?(?:\s+(virtual))?(?:.*?prio=…)?…` | `ParserHotSpotCore.java:48-58` | THREAD_HEADER |
| `^#\d+\s+"(.*?)"\s+(RUNNABLE\|…)\b` | `:82-83` | THREAD_HEADER_JCMD (jcmd `-format=text`) |
| `\b(RUNNABLE\|…)\b(?:\s+on\s+(\S+))?` | `:75-76` | INLINE_STATE (ThreadMXBean) |
| `java\.lang\.Thread\.State:\s*(\S+)` | `:69-70` | THREAD_STATE |
| `^\s+at (.+)` | `:86-87` | STACK_FRAME |
| `- locked <(.+?)>(?:\s+\(a (.+?)\))?` | `:91-92` | LOCKED (endereço verbatim, classe tokenizada) |
| `- (?:waiting on\|waiting to lock\|parking to wait for)\s+<(.+?)>` | `:93-94` | WAITING_ON (endereço verbatim — chave de agrupamento do LockContention **e** do diff) |
| `<virtual thread is mounted on carrier thread "(.+?)">` | `:61-62` | CARRIER_THREAD |
| `<pinned:\s*synchronized>` | `:65-66` | PINNED_MARKER |
| `Carrying virtual thread #(\d+)` | `:63-64` | CARRYING_VIRTUAL |
| `JRE\s+([\d._]+)\|java version "([^"]+)"\|Full thread dump.*?\((\d+[\d._]+)` | `:97-99` | JVM_VERSION |
| `(HotSpot\|OpenJDK\|GraalVM\|Zing)` | `:100-101` | JVM_VENDOR |
| `^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})` | `:104-105` | TIMESTAMP_DUMP |
| `Full thread dump .*(Java HotSpot\|OpenJDK)` | `DetectorFormatoServiceImpl.java:17-18` | HOTSPOT_PATTERN |
| `Full thread dump.*Zing` | `:25-26` | ZING_PATTERN |
| `Full thread dump.*GraalVM` | `:29-30` | GRAALVM_PATTERN |
| `1TISIGINFO\|3XMTHREADINFO\|1XMJAVAVERSION` | `:33-34` | OPENJ9_PATTERN |
| `(?m)^"[^"]*" Id=\d+ (?:RUNNABLE\|…)\b` | `:40-41` | THREADMXBEAN_PATTERN |
| `(?m)^#\d+ "[^"]*" (?:RUNNABLE\|…)\b` | `:46-47` | JCMD_TEXT_PATTERN |

---

## 8. Entradas ambíguas e como foram decididas

| # | Ambiguidade | Decisão | Justificativa |
|---|---|---|---|
| 1 | `threadNameExact` sem candidatos | deixado `[]` | nenhuma fonte casa nome por igualdade; forçar entradas ali criaria divergência com o `startsWith` do servidor |
| 2 | `^ForkJoinPool-\d+-worker-\d+$` sem match por nome no código | **required** | mandato da SPEC §3 + AVALIACAO §1.2 item 4; nome gerado pelo JDK, zero conteúdo de app; é a chave de `AgrupamentoCarrier` |
| 3 | `io.grpc.` (não está em nenhuma lista de prefixos) | **required** | os comentários em `PadroesDeteccao.java:238-239` e `:304-305` declaram que o `contains()` existe para cobrir Netty shaded via gRPC; tokenizar quebraria detecção de I/O idle |
| 4 | `com.datastax.` (mesmo caso do gRPC, citado no comentário `:305`) | **recommended** | o comentário cita Cassandra como exemplo de shading, mas nenhum padrão do código nomeia `com.datastax`; preservado por default, tokenizável com `--strict` |
| 5 | `org.apache.` largo vs. `org.apache.tomcat.`/`.catalina.`/`.coyote.` estreitos | required = `org.apache.` | `DetectorThreadOrfa.java:94` e `RenderizadorPrompt.java:67` já usam o largo; a UNIÃO exige o mais largo |
| 6 | `org.eclipse.` vs `org.eclipse.jetty.` | required = `org.eclipse.` | idem (`RenderizadorPrompt.java:67`) |
| 7 | `hibernate`, `hikari`, `okhttp3`, `kafka`, `aws-sdk` (o enunciado sugeria como *recommended*) | **required** | todos aparecem em padrões de detecção reais (§1 #11, #26, #21, #7, #29/#30) — são paridade, não cortesia |
| 8 | `com.zaxxer.hikari` / `com.mchange.v2.c3p0` sem ponto final no código | gravado **com** ponto final | evita casar `com.zaxxer.hikariXYZ`; nenhum frame real é exatamente o prefixo sem ponto |
| 9 | Prefixos de nome muito largos: `Timer`, `parallel-`, `GC ` | mantidos required | são o que o servidor usa; consequência declarada: uma thread do app chamada `TimerDeCobrancaTenantAcme` seria **preservada verbatim** (vazamento) — o preço de manter paridade. Ver §10 |
| 10 | `PREFIXOS_SCHEDULER` (`scheduling-`, `TaskScheduler-`…) são defaults de framework mas o prefixo é **configurável** pelo app (`spring.task.scheduling.thread-name-prefix`) | required só os defaults literais | prefixo custom é do app → tokenizado → cai no fallback por stack do DetectorProblemaScheduler (AVALIACAO §1.2 item 9b, desvio aceito) |
| 11 | Regexes com `Pattern.CASE_INSENSITIVE` | flag materializada como `(?i)` inline | o JSON não carrega flags; sem isso um consumidor perderia `gc thread#1` minúsculo |
| 12 | `TimerQueue`, `GC Thread`, `VM Periodic Task Thread` subsumidos por entradas mais curtas | **mantidos** na lista | redundância é inócua num match set e deixa a prova da UNIÃO verificável linha a linha |

---

## 9. Padrões do código que **não** couberam no schema da SPEC §3

Nenhum destes é allowlist (não é "preservar verbatim"), mas todos são restrições reais que o tm-anon precisa honrar. Ficam registrados aqui porque saíram da mesma auditoria.

| Padrão | Origem | Por que não é allowlist | Onde já está tratado |
|---|---|---|---|
| `POOL_GENERICO` = `^(.+?)[-#](\d+)$` | `PadroesDeteccao.java:23`, usado por `extrairPrefixoPool` `:383-386` | é **regra de reescrita**: tokenizar o prefixo e **manter separador + número** | SPEC §5.3c |
| `EXTENSAO_ARQUIVO_WEB` = `.*\.(css\|js\|…)$` | `PadroesDeteccao.java:392-395` | é **restrição de forma do token** (o token não pode terminar em extensão web) | SPEC §1 invariante 2 · §5.3b |
| `ID_REQUEST` = `.*(UUID\|[0-9a-fA-F]{16,}\|\d{8,}).*` | `:397-400` | idem — proíbe run de hex ≥16 e de dígitos ≥8 **dentro** do token | SPEC §1 invariante 3 |
| `ehNomeDeRequestOuRota` (`/`, `?`) | `:407-412` | idem + define quem ganha o sufixo `/q` | SPEC §1 (marcador de rota) · §5.3b |
| `stackContemPadrao` usa `contains()` | `:369-372` | restrição de **alfabeto** do token (não pode conter `java.io.`, `Consumer.receive`…) | SPEC §1 invariante 1/4 |
| `MAX_TAMANHO_LINHA = 50_000` | `ParserHotSpotCore.java:39,184` | linhas acima disso são **ignoradas** pelo parser; a máscara não pode inflar uma linha para além do limite | não coberto — anotado no relatório |
| `MAX_LINHAS`, `MAX_THREADS`, `TIMEOUT_PARSE` | `:41-45` | guardas anti-DoS; a máscara não altera contagem de linhas (regra de strip da SPEC §5.7 já preserva) | SPEC §5.7 |
| `DetectorDeadlock.THREAD_NAME_IN_DEADLOCK` = `"(.+?)"` | `DetectorDeadlock.java:23-24` | não é nome preservado: exige que os **mesmos tokens** dos cabeçalhos apareçam entre aspas no bloco | SPEC §5.5 |

---

## 10. Riscos conhecidos desta allowlist

1. **Prefixos largos preservam nome de app.** `Timer`, `parallel-`, `GC `, `Finalizer` casam por `startsWith`: uma thread do app cujo nome comece com um deles sai **verbatim**. É o comportamento do servidor (ela já é tratada como interna da JVM hoje), então preservar mantém paridade — mas é vazamento potencial. Recomendação: o `verify` do tm-anon deve **listar** os nomes preservados por prefixo largo para inspeção humana, e o `--strict` pode rebaixá-los.
2. **Acoplamento.** Toda entrada aqui espelha código do servidor neste commit. Um padrão novo em `PadroesDeteccao` sem espelho aqui degrada detecção silenciosamente — o teste de contrato no CI do produto previsto na AVALIACAO §4 (Riscos) é o que fecha esse buraco.
3. **Listas paralelas divergentes no próprio servidor.** `PREFIXOS_FRAMES_INFRA` (`PadroesDeteccao.java:251-259`), a local de `DetectorThreadOrfa` (`:86-98`), a de `CatalogoRecomendacaoAcao` (`:580-596`), a de `RenderizadorPrompt` (`:64-68`) e a de `HeuristicaInteressante` (`:23-29`) **não são iguais** — cada uma tem itens que as outras não têm. A allowlist é a UNIÃO das cinco, o que é o mais conservador para o tm-anon, mas o débito de extrair um util único no servidor (já anotado em `HeuristicaInteressante.java:22`) segue aberto.
