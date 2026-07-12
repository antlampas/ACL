<!--
Title: Sistema ACL - Documento Progettuale-Architetturale
Author/Licensor: Francesco
Source: this repository
License: Creative Commons Attribution-ShareAlike 4.0 International
License URL: https://creativecommons.org/licenses/by-sa/4.0/
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Sistema ACL - Documento Progettuale-Architetturale

## 1. Scopo e principi guida

Il sistema ACL definisce **chi** puo eseguire **quale operazione** su **quale
risorsa**, con quale **verdetto**. L'unita atomica e' l'`ACLEntry`: una
dichiarazione persistita che combina soggetto, risorsa, operazione, permesso e
criteri di profilo.

Il documento descrive un sottosistema ACL riusabile, indipendente dai domini
applicativi. Le applicazioni consumatrici forniscono il catalogo delle
operazioni, la gerarchia delle risorse, la risoluzione dell'identita e la
persistenza.

Principi guida:

1. **Autorizzazione dichiarativa a entry.** Ogni decisione deriva da `ACLEntry`
   persistite. Il dominio consumatore non deve cablare regole di accesso nelle
   proprie entita.
2. **Autenticazione separata dall'autorizzazione.** Il sistema ACL non autentica:
   riceve una richiesta autorizzativa con identita gia risolta e decide solo se
   l'operazione e' consentita.
3. **Qualificazione per livello e gruppo.** Ogni entry e' qualificata da un
   livello, da un gruppo o da entrambi, valutati contro il profilo del
   richiedente.
4. **Decisione pura e stateless.** La policy di autorizzazione e' una funzione
   deterministica che consulta solo porte astratte. Cache, database,
   credenziali, identity provider, protocolli e framework sono adapter esterni.
5. **Default deny e precedenza conservativa.** In assenza di concessione
   esplicita si nega; ogni `DENY` matchante prevale su ogni `ALLOW`.
6. **Enforcement interfaccia-agnostico al confine.** Qualunque origine produce
   una richiesta normalizzata (`AuthorizationRequest`) prima dei casi d'uso. I
   service interni proteggono solo operazioni sensibili proprie, come gestione
   ACL e profili.
7. **Nessuna ownership implicita.** Il creatore puo ricevere privilegi tramite
   seeding di entry ordinarie, revocabili e ispezionabili; non esiste un bypass
   speciale del proprietario.

---

## 2. Registro delle decisioni di progetto

| # | Nodo | Decisione adottata |
|---|------|--------------------|
| D1 | Ruolo di soggetto, livello e gruppo | Sono criteri indipendenti e componibili. Ogni entry dichiara come combinarli tramite `profile_join` e `subject_join`. |
| D2 | Operazione e permesso | **Operazione** = azione governata (`VIEW`, `EDIT`, `MANAGE_ACL`, ...). **Permesso** = verdetto `ALLOW` o `DENY`. |
| D3 | Livelli e conflitti | Un requisito di livello `L` e' soddisfatto da chi ha `profile.level <= L`. La precedenza e' `DENY > ALLOW > DENIED`. |
| D4 | Risorse e ambiti | Il modello supporta risorse concrete, radici di tipo `<TYPE>:*`, `SYSTEM:global`, soggetto `PUBLIC`, gerarchia ed ereditarieta. |
| D5 | Profilo anonimo | I richiedenti anonimi ricevono `Profile(level = ANON_SENTINEL, groups = {"public"})`, cosi livello e gruppo sono sempre valutabili. |
| D6 | Gruppi multipli | Un profilo puo appartenere a piu gruppi; i gruppi sono criteri di profilo, non soggetti ACL. |
| D7 | Seeding al posto dell'ownership | La creazione di una risorsa puo materializzare entry iniziali tramite `SeedingPolicy`; sono entry ordinarie, revocabili e soggette a `DENY`. |
| D8 | Orientamento numerico del livello | Numero piu basso = profilo piu privilegiato; numero alto = profilo meno privilegiato. |
| D9 | Catalogo operazioni | Ogni operazione dichiara almeno `read_only`, `inheritable` e `protected`. |
| D10 | Mutazioni e anonimo | Nessuna entry `ALLOW` su operazione mutante puo essere soddisfatta dal profilo anonimo. |
| D11 | Autoprotezione gestione ACL | Modificare entry tramite richieste di gestione richiede `MANAGE_ACL` sulla risorsa concreta oppure su `SYSTEM:global`; `SYSTEM:global` e radici `<TYPE>:*` richiedono sempre `MANAGE_ACL` globale. Gli hook di ciclo vita interni sono invocabili solo da casi d'uso gia autorizzati o dal bootstrap. |
| D12 | Profili e grant protetti | Modificare livelli/gruppi e concedere operazioni protette sono responsabilita separate, mediate da `MANAGE_PROFILES` e `GrantConstraintPolicy`. |
| D13 | Richieste interfaccia-agnostiche | Il confine traduce qualunque invocazione in una richiesta autorizzativa normalizzata; il nucleo ACL non conosce canali, protocolli o runtime di origine. |

---

## 3. Modello concettuale

### 3.1 `ACLEntry`

Un'`ACLEntry` esprime una singola affermazione di autorizzazione.

```text
ACLEntry
  id            : ACLEntryId
  subject       : SubjectRef        # USER(id) | PUBLIC, estendibile a SERVICE
  resource      : ResourceRef       # SYSTEM:global | <TYPE>:* | <TYPE>:<id>
  operation     : OperationName
  permission    : Permission        # ALLOW | DENY
  level         : int?              # soddisfatto se profile.level <= level
  group         : GroupId?          # soddisfatto se group in profile.groups
  profile_join  : OR | AND          # default: OR
  subject_join  : AND | OR          # default: AND
```

`level` e `group` sono criteri di profilo: almeno uno deve essere presente
(INV-1). Questo consente di rappresentare sia concessioni per tier, sia
concessioni per gruppo, sia entry ancorate a un singolo soggetto usando la soglia
universale.

### 3.2 `SubjectRef`

Il soggetto e' il criterio identitario dell'entry.

| Tipo | Descrizione |
|------|-------------|
| `USER(id)` | Un principal specifico: account, utente locale o service account modellato come utente applicativo. |
| `PUBLIC` | Nessuna restrizione identitaria; include anche il richiedente anonimo. |
| `SERVICE(id)` | Estensione opzionale per domini che vogliono distinguere soggetti macchina da utenti umani. |

Il modello base richiede solo `USER` e `PUBLIC`. Se un dominio non vuole
estendere i tipi di soggetto, i service account possono essere rappresentati come
`USER(account_id)`.

`PUBLIC` non significa automaticamente "accesso anonimo": l'entry deve comunque
matchare i criteri di profilo. Su operazioni mutanti vale INV-2, quindi il
profilo anonimo non puo mai ottenere un `ALLOW`.

### 3.3 `ResourceRef`

Una risorsa e' una coppia `(type, id)`.

| Forma | Significato |
|-------|-------------|
| `SYSTEM:global` | Ambito per operazioni senza risorsa specifica: creazioni globali, gestione profili, privilegi amministrativi, estensioni non mappate. |
| `<TYPE>:*` | Radice di tipo: default e soglie per una categoria di risorse, per esempio `PHOTO:*` o `MISSION:*`. |
| `<TYPE>:<id>` | Risorsa concreta del dominio consumatore. |

Il sistema ACL non conosce i tipi concreti. Il dominio consumatore registra le
radici che usa e implementa `ResourceHierarchyProvider` per esporre i padri di
una risorsa concreta. Le radici di tipo e `SYSTEM:global` non hanno padri salvo
scelta esplicita del consumatore, sconsigliata per mantenere chiari i confini
amministrativi.

### 3.4 `OperationSpec`

L'operazione e' l'azione governata. Il catalogo e' aperto, ma ogni operazione
deve avere una specifica:

```text
OperationSpec
  name        : str
  read_only   : bool
  inheritable : bool = true
  protected   : bool = false
```

Campi:

- `read_only`: distingue letture da mutazioni ed e' usato dall'invariante
  anti-anonimo (INV-2).
- `inheritable`: abilita o vieta il fallback ai padri. `MANAGE_ACL` dovrebbe
  essere sempre non ereditabile.
- `protected`: segnala operazioni che richiedono vincoli ulteriori quando vengono
  concesse tramite ACL, per esempio `MANAGE_ACL`, `MANAGE_PROFILES`,
  `MANAGE_IDENTITIES` o permessi equivalenti del dominio.

Catalogo di esempio non normativo:

| Operazione | `read_only` | `inheritable` | `protected` | Risorsa tipica |
|------------|:-----------:|:-------------:|:-----------:|----------------|
| `VIEW` | si | si | no | Risorsa concreta o radice di tipo |
| `LIST` | si | si | no | Risorsa concreta o radice di tipo |
| `CREATE` / `CREATE_*` | no | dipende dal dominio | no | `SYSTEM:global` o padre delegabile |
| `EDIT` | no | si | no | Risorsa concreta |
| `DELETE` | no | si | no | Risorsa concreta |
| `UPLOAD` / `ASSIGN` | no | dipende dal dominio | no | Sistema, galleria, missione o altra risorsa target |
| `MANAGE_ACL` | no | no | si | Risorsa concreta o `SYSTEM:global` |
| `MANAGE_PROFILES` | no | no | si | `SYSTEM:global` |
| `EXECUTE` | no | no | si | `SYSTEM:global` per estensioni non mappate |

### 3.5 `Permission`

| Valore | Significato |
|--------|-------------|
| `ALLOW` | L'entry concede l'operazione se matcha il richiedente. |
| `DENY` | L'entry nega l'operazione se matcha il richiedente. |

`DENY` prevale su `ALLOW` nella risoluzione.

### 3.6 Livello

Il livello e' un intero non negativo. Un criterio `level = L` e' soddisfatto
quando:

```text
profile.level <= L
```

Conseguenze:

- un numero basso identifica un profilo piu privilegiato;
- un `ALLOW` con soglia alta e' ampio;
- un `DENY` con soglia alta e' molto restrittivo, perche matcha molti profili;
- `ANON_SENTINEL` e' il livello meno privilegiato e puo essere usato come
  **soglia universale**, soddisfatta da chiunque.

La soglia universale serve per entry "legate al solo soggetto" rispettando
INV-1. Esempio: `ALLOW VIEW USER(alice) level=ANON_SENTINEL` concede a `alice`
indipendentemente dal suo tier corrente.

### 3.7 Gruppo

Il gruppo e' un criterio di profilo. Un criterio `group = G` e' soddisfatto
quando:

```text
G in profile.groups
```

Il gruppo `"public"` e' implicito per ogni profilo, incluso quello anonimo. Non
e' una membership ordinaria da assegnare o rimuovere: e' il criterio universale
per esprimere letture davvero pubbliche, come `ALLOW VIEW PUBLIC group=public`.

I gruppi esterni, per esempio provenienti da OIDC o da un IdP, non sono
autorevoli per default. Possono alimentare `profile.groups` solo tramite una
policy esplicita, deterministica e auditable del progetto consumatore.

### 3.8 `Profile`

Il profilo e' il value object autorizzativo risolto a ogni richiesta.

```text
Profile
  level   : int
  groups  : frozenset[GroupId]     # include sempre "public"
  version : int?                   # opzionale, utile per cache/revoca
```

Il profilo anonimo e':

```text
Profile(level = ANON_SENTINEL, groups = {"public"})
```

Un soggetto non autenticato, inesistente, disabilitato o non verificabile riceve
il profilo anonimo. In questo modo la valutazione non contiene rami speciali:
anche l'anonimo passa dallo stesso algoritmo.

### 3.9 Richieste autorizzative normalizzate

Il confine del sottosistema ACL riceve richieste, non interfacce utente. Ogni
invocazione esterna o interna viene normalizzata in un oggetto esplicito prima
di raggiungere i service applicativi.

```text
AuthorizationRequest
  identity  : RequestIdentity
  operation : OperationName
  resource  : ResourceRef
  metadata  : map?              # opzionale, solo audit/correlazione

CandidateResourcesRequest
  identity      : RequestIdentity
  operation     : OperationName
  resource_type : str
  metadata      : map?

RequestIdentity
  subject       : SubjectRef
  authenticated : bool
  auth_method   : str?
  authz_version : int?
```

`AuthorizationRequest` e `CandidateResourcesRequest` sono contratti applicativi,
non DTO di trasporto. Il loro `metadata` non partecipa alla decisione ACL, salvo
che il dominio consumatore lo trasformi prima in profilo autorevole, operazione
o risorsa tramite policy esplicita e auditabile.

Il mapping da invocazione concreta a `(identity, operation, resource)` e'
responsabilita del confine di normalizzazione. Payload esterni non possono
imporre direttamente il subject effettivo, alzare il livello del profilo o
selezionare una risorsa diversa da quella derivata dal contesto affidabile.

### 3.10 Invarianti strutturali e di grant

Gli invarianti sono applicati prima della persistenza, indipendentemente dal
canale che ha prodotto la richiesta.

| ID | Invariante |
|----|------------|
| **INV-1** | Ogni `ACLEntry` ha almeno uno tra `level` e `group`. |
| **INV-2** | Nessuna entry `ALLOW` su operazione non `read_only` puo matchare il profilo anonimo. Il controllo si esprime valutando l'entry contro `SubjectRef(PUBLIC)` e `Profile.anonymous()`. |
| **INV-3** | `level`, se presente, e' un intero `>= 0`; `group`, se presente, e' non vuoto. |
| **INV-4** | `profile_join` e `subject_join` sono valori validi; i default sono `OR` e `AND`. |
| **INV-5** | `subject = PUBLIC` con `subject_join = OR` e' vietato: renderebbe vacui i criteri di profilo. |
| **INV-6** | Entry su `SYSTEM:global` e radici `<TYPE>:*` sono modificabili solo da chi ha `MANAGE_ACL` su `SYSTEM:global`. |
| **INV-7** | Entry che concedono operazioni `protected` devono passare da `GrantConstraintPolicy`. |

INV-2 sostituisce la forma piu rigida "`PUBLIC` solo read-only". La forma
anti-anonimo conserva la sicurezza, ma permette entry come `ALLOW EDIT PUBLIC
group=editors`: il soggetto e' pubblico solo come "nessuna restrizione
identitaria", mentre il gruppo esclude l'anonimo.

---

## 4. Diagramma concettuale

```text
                         +--------------------------------+
                         |            ACLEntry            |
                         +--------------------------------+
      chi -------------->| subject   : USER|PUBLIC|SERVICE|
      su cosa ---------->| resource  : SYSTEM|TYPE:*|id   |<--- gerarchia
      quale azione ----->| operation : OperationName      |<--- OperationCatalog
      verdetto --------->| permission: ALLOW|DENY         |
                         | level?    : soglia <=          |
                         | group?    : appartenenza       |
                         | profile_join / subject_join    |
                         +----------------+---------------+
                                          |
                                          | valutata contro
                                          v
                         +--------------------------------+
                         |            Profile             |
                         | level : int                    |
                         | groups: {..., "public"}        |
                         +--------------------------------+
```

---

## 5. Semantica di valutazione

La domanda e' sempre:

```text
is_allowed(subject, operation, resource) -> Decision
```

dove `Decision` e' almeno `ALLOWED` o `DENIED`; una implementazione puo arricchirla
con una traccia per audit amministrativo.

### 5.1 Match di una entry

Per una entry e un richiedente:

```text
subjectMatch = entry.subject == PUBLIC
            OR entry.subject == subject               # USER/SERVICE identificati

levelMatch   = profile.level <= entry.level           # solo se level presente
groupMatch   = entry.group in profile.groups          # solo se group presente

profilePart  = profile_join sui criteri presenti
matches      = subject_join(subjectMatch, profilePart)
```

`profile_join` combina solo i criteri presenti. Per INV-1 ce n'e' sempre almeno
uno.

Casi tipici con `subject_join = AND`:

| Subject | Level | Group | Significato |
|---------|:-----:|:-----:|-------------|
| `PUBLIC` | - | `public` | Chiunque, incluso anonimo; valido solo per letture o altri casi che non violano INV-2. |
| `PUBLIC` | `L` | - | Chiunque abbia `profile.level <= L`; utile per soglie di bootstrap. |
| `PUBLIC` | `L` | `G` | Con `profile_join=OR`: livello sufficiente oppure gruppo `G`. |
| `PUBLIC` | `L` | `G` | Con `profile_join=AND`: livello sufficiente e gruppo `G`. |
| `USER(a)` | `ANON_SENTINEL` | - | Solo l'utente `a`, indipendentemente dal profilo. |
| `USER(a)` | `L` | - | L'utente `a`, solo se ha anche livello `<= L`. |

`subject_join = OR` e' espressivo ma pericoloso: `USER(a) OR level<=L` concede
ad `a` oppure a chiunque soddisfi la soglia. E' ammesso solo quando non viola
INV-2 e non usa `PUBLIC` come soggetto.

### 5.2 Risoluzione

Algoritmo normativo:

1. Risolvi `OperationSpec` da `OperationCatalog`.
2. Risolvi il `Profile` del soggetto da `ProfileProvider`.
3. Carica le entry proprie per `(resource, operation)`.
4. Se esiste almeno una entry propria, la decisione si chiude su quelle:
   - se una `DENY` matcha -> `DENIED`;
   - altrimenti se una `ALLOW` matcha -> `ALLOWED`;
   - altrimenti -> `DENIED`.
5. Se non ci sono entry proprie e `operation.inheritable = true`, valuta i padri
   forniti da `ResourceHierarchyProvider`.
6. Con piu padri usa una OR non permissiva: un `DENY` matchante in qualunque
   ramo padre blocca le concessioni provenienti dagli altri padri.
7. Solo se nessun ramo padre contiene un `DENY` matchante, basta almeno un padre
   `ALLOWED` per ottenere `ALLOWED`.
8. Se nessun padre concede, o l'operazione non e' ereditabile, l'esito e'
   `DENIED`.

```text
evaluate(resource) -> EvaluationResult:
  own = entries_for(resource, operation)
  if own:
    matching = [entry for entry in own if matches(entry, subject, profile)]
    if any(entry.permission == DENY for entry in matching):
      return EvaluationResult(DENIED, explicit_deny = true)
    if any(entry.permission == ALLOW for entry in matching):
      return EvaluationResult(ALLOWED)
    return EvaluationResult(DENIED)

  if not operation.inheritable:
    return EvaluationResult(DENIED)

  parent_results = [evaluate(parent) for parent in parents_of(resource)]
  if any(result.explicit_deny for result in parent_results):
    return EvaluationResult(DENIED, explicit_deny = true)
  if any(result.decision == ALLOWED for result in parent_results):
    return EvaluationResult(ALLOWED)
  return EvaluationResult(DENIED)
```

La guardia anti-ciclo e' obbligatoria. Una risorsa con anche una sola entry
propria per l'operazione non eredita quella operazione dai padri, nemmeno se
l'entry propria non matcha.

Il flag interno `explicit_deny` non cambia l'API pubblica, che restituisce
`ALLOWED` o `DENIED`; serve alla policy e alla trace per distinguere un diniego
causato da un `DENY` matchante da un semplice default deny. Solo il primo blocca
le concessioni degli altri padri.

### 5.3 Ereditarieta

L'ereditarieta e' unidirezionale: figlio verso padre. Esempi:

- `PHOTO:<id> -> GALLERY:<id>` per foto contenute in gallerie;
- `ACTIVITY:<id> -> OBJECTIVE:<id> -> ASSIGNMENT:<id> -> MISSION:<id> -> MISSION:*`;
- `PERSON:<id> -> PERSON:*`;
- `GROUP:<id> -> GROUP:*`.

La struttura concreta e' dominio-specifica. Il sistema ACL richiede solo che
`ResourceHierarchyProvider.parents_of(resource)` restituisca una lista finita di
padri e che la policy protegga dai cicli.

In presenza di padri multipli, l'ereditarieta resta figlio -> padre ma non e'
permissiva: un ramo che incontra un `DENY` matchante rende l'esito `DENIED`
anche se un altro ramo avrebbe prodotto `ALLOWED`. Un ramo che termina in
default deny, senza `DENY` matchante, non blocca invece gli `ALLOW` degli altri
padri.

`MANAGE_ACL` e le altre operazioni amministrative dovrebbero essere non
ereditabili: gestire le entry di una risorsa figlia deve restare una scelta
esplicita sulla risorsa stessa o un privilegio globale.

### 5.4 `SYSTEM:global` e radici di tipo

`SYSTEM:global` rappresenta operazioni senza risorsa specifica:

- creazione di nuove risorse (`CREATE`, `CREATE_MISSION`, ...);
- gestione profili, identita, account e bootstrap;
- privilegi amministrativi globali;
- richieste di estensione non mappabili su una risorsa concreta.

`<TYPE>:*` rappresenta invece il default di una categoria di risorse. Radici di
tipo e `SYSTEM:global` sono utili per seminare soglie come:

```text
ALLOW VIEW  PUBLIC level=read_threshold  resource=PHOTO:*
ALLOW EDIT  PUBLIC level=write_threshold resource=PHOTO:*
ALLOW MANAGE_ACL PUBLIC level=admin_threshold resource=SYSTEM:global
```

Le entry su `SYSTEM:global` e radici di tipo sono entry ordinarie in valutazione,
ma non in gestione: per modificarle serve `MANAGE_ACL` globale (INV-6).
Poiche `MANAGE_ACL` non e' ereditabile, una entry `MANAGE_ACL` su `<TYPE>:*`
non concede automaticamente la gestione delle ACL delle risorse concrete di quel
tipo: per quelle serve una entry sulla risorsa concreta oppure `MANAGE_ACL` su
`SYSTEM:global`.

### 5.5 Risorse candidate per liste

Per liste per-soggetto, la policy puo esporre:

```text
candidate_resources(subject, operation, resource_type) -> list[ResourceRef]
```

Il metodo raccoglie risorse con almeno una `ALLOW` matchante, di solito tramite
`ACLEntryRepository.list_by_operation(operation, resource_type)`. Non e' una
decisione definitiva: il chiamante deve filtrare ogni candidata con
`is_allowed()` per applicare `DENY`, entry proprie non matchanti ed ereditarieta,
incluso il blocco da `DENY` ereditato in qualunque ramo padre.
Il metodo non deve essere interpretato come enumerazione completa dei discendenti
accessibili tramite ereditarieta: per liste gerarchiche il dominio consumatore
deve combinare candidate esplicite, query di dominio sui figli dei padri
candidati e filtro finale con `is_allowed()`.

Per grandi dataset l'implementazione puo ottimizzare con:

- prefiltri su `subject_type`, `subject_id`, `group` e `resource_type`;
- caricamento batch delle entry;
- cache per-richiesta delle entry dei padri;
- indici su `(resource_type, resource_id, operation)` e `(subject_type,
  subject_id)`.

### 5.6 Seeding automatico

Senza ownership implicita, una risorsa appena creata non avrebbe permessi propri.
Il seeding automatico risolve il problema materializzando entry ordinarie nella
stessa transazione della creazione.

```text
SeedingPolicy
  enabled        : bool
  resource_type  : str
  operations     : set[OperationName]
  grant_to       : CREATOR | CREATOR_GROUP | NONE
  level_strategy : UNIVERSAL | CREATOR_LEVEL | FIXED
```

Forma default per il creatore:

```text
ALLOW <operation>
  subject      = USER(creator)
  level        = ANON_SENTINEL
  subject_join = AND
```

Il dominio consumatore decide quali operazioni seminare per tipo:

- risorse che devono nascere private possono seminare `VIEW`, `EDIT`, `DELETE` e
  `MANAGE_ACL`;
- risorse che devono ereditare la visibilita dal padre possono seminare solo
  mutazioni operative e `MANAGE_ACL`;
- risorse che devono restare governate da default globali possono seminare solo
  `MANAGE_ACL` oppure nulla.

Le entry seminate sono revocabili, ispezionabili, soggette a INV-1..INV-7 e alla
precedenza `DENY > ALLOW`.

---

## 6. Architettura

Il sistema segue Ports & Adapters. Le dipendenze puntano verso il nucleo.

```text
+--------------------------------------------------------------+
| Confine / Normalizzazione richieste                          |
| RequestNormalizer, IdentityResolver, DeniedResponseMapper     |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Application Facade                                            |
| AuthorizationService, ACLService, BootstrapService            |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Policy                                                        |
| AuthorizationPolicy: match, precedenza, ereditarieta          |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Ports                                                         |
| Repositories, ProfileProvider, ResourceHierarchyProvider,     |
| OperationCatalog, GrantConstraintPolicy                       |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Domain                                                        |
| ACLEntry, SubjectRef, ResourceRef, OperationSpec, Profile     |
+--------------------------------------------------------------+
```

### 6.1 Domain

Contiene solo oggetti e funzioni pure:

- `ACLEntry`, `SubjectRef`, `ResourceRef`, `OperationSpec`, `Profile`;
- enum/value object `Permission`, `JoinOp`, `Decision`;
- funzioni `subject_matches`, `profile_part_matches`, `entry_matches`,
  `resolve`;
- invarianti `ACLEntryInvariants`.

Il domain non importa repository, framework, sessioni o database.

### 6.2 Ports

| Porta | Responsabilita |
|-------|----------------|
| `ACLEntryRepository` | `entries_for(resource, operation)`, `list_by_operation(operation, resource_type)`, CRUD entry, `replace_entries`, `delete_by_resource`, `delete_by_subject`. |
| `IdentityResolver` | Risolve `RequestIdentity` da un contesto di invocazione gia acquisito dal confine. |
| `ProfileProvider` | Risolve `Profile` corrente per un `SubjectRef`; restituisce il profilo anonimo se il soggetto non e' valido. |
| `ResourceHierarchyProvider` | Restituisce i padri di una risorsa. |
| `OperationCatalog` | Restituisce `OperationSpec` per nome operazione. |
| `GrantConstraintPolicy` | Valida se il chiamante puo concedere una entry, soprattutto per operazioni `protected`. |
| `PrincipalBindingPort` | Opzionale: collega il principal del sottosistema Auth a entita locali del dominio consumatore. |

### 6.3 `AuthorizationPolicy`

E' la decisione pura.

```text
AuthorizationPolicy
  is_allowed(subject, operation, resource) -> Decision
  candidate_resources(subject, operation, resource_type) -> list[ResourceRef]
  explain(subject, operation, resource) -> DecisionTrace
```

Responsabilita:

- risolvere profilo e specifica operazione;
- caricare entry proprie;
- applicare match e precedenza;
- valutare i padri se l'operazione e' ereditabile, applicando il blocco da
  `DENY` matchante in qualunque ramo padre;
- proteggere dai cicli;
- produrre una traccia esplicativa per audit/debug amministrativo.

`explain` non deve essere esposto a utenti finali non autorizzati: puo rivelare
struttura interna delle ACL.

### 6.4 `AuthorizationService`

Facade applicativa sopra la policy.

```text
AuthorizationService
  is_allowed(request: AuthorizationRequest) -> bool
  require(request: AuthorizationRequest) -> None
  candidate_resources(request: CandidateResourcesRequest) -> list[ResourceRef]
  explain(request: AuthorizationRequest) -> DecisionTrace
```

`require` traduce `DENIED` in un errore applicativo dedicato (`AuthorizationDenied`
o equivalente). Il confine chiamante lo mappa nell'esito appropriato per il
proprio protocollo o meccanismo di invocazione.

### 6.5 `ACLService`

`ACLService` gestisce le entry; non decide l'accesso ordinario.

```text
ACLService
  list_entries(identity, resource) -> list[ACLEntryDTO]
  create_entry(identity, input) -> ACLEntryDTO
  update_entry(identity, entry_id, changes) -> ACLEntryDTO
  delete_entry(identity, entry_id) -> None
  replace_entries(identity, resource, inputs) -> None
  delete_by_resource(resource) -> None
  delete_by_subject(subject) -> None
  on_resource_created(resource, creator, resource_type) -> None
  ensure_bootstrap_entries() -> None
```

Regole:

- valida INV-1..INV-7 prima di ogni persistenza;
- i metodi di gestione esposti al chiamante (`list_entries`, `create_entry`,
  `update_entry`, `delete_entry`, `replace_entries`) richiedono `MANAGE_ACL`
  sulla risorsa concreta o su `SYSTEM:global`;
- gli stessi metodi, quando operano su `SYSTEM:global` o `<TYPE>:*`, richiedono
  sempre `MANAGE_ACL` su `SYSTEM:global`;
- quando una entry `ALLOW` concede operazioni `protected`, invoca
  `GrantConstraintPolicy`;
- `replace_entries` deve essere atomico rispetto alla risorsa;
- `on_resource_created`, `delete_by_resource` e `delete_by_subject` sono hook di
  ciclo vita interni: non sono endpoint di amministrazione ACL e possono essere
  invocati solo da casi d'uso gia autorizzati o dal bootstrap;
- `on_resource_created` applica `SeedingPolicy` nella stessa transazione della
  creazione della risorsa, oppure con compensazione esplicita se il dominio non
  puo condividere una transazione;
- `delete_by_resource` e `delete_by_subject` sono usati per cascade sicure quando
  una risorsa o un soggetto vengono eliminati.

### 6.6 Enforcement interfaccia-agnostico al confine

Ogni canale, processo o integrazione deve produrre una richiesta normalizzata e
invocare `AuthorizationService.require` oppure il service applicativo
autoprotetto. Il sottosistema ACL non distingue chi o cosa ha originato la
richiesta.

Pipeline normativa:

1. il confine riceve un contesto di invocazione opaco per il core ACL;
2. `IdentityResolver` produce `RequestIdentity`;
3. `RequestNormalizer` determina `operation` e `resource` da regole affidabili
   del dominio consumatore;
4. una richiesta ordinaria diventa `AuthorizationRequest` e passa da
   `AuthorizationService.require`;
5. una richiesta di gestione ACL passa da `ACLService`, che applica i gate
   `MANAGE_ACL` piu precisi;
6. gli errori applicativi vengono trasformati dal confine nell'esito esterno
   appropriato, senza esporre trace non autorizzate.

Se una richiesta non e' mappabile in modo univoco, il normalizzatore deve
fallire chiuso. Un consumatore puo configurare fallback conservativi, per
esempio una operazione protetta su `SYSTEM:global`, ma non fallback permissivi.

### 6.7 Direzione delle dipendenze

```text
request adapters     -> RequestNormalizer | IdentityResolver
request adapters     -> AuthorizationService | ACLService
RequestNormalizer    -> Domain
AuthorizationService -> AuthorizationPolicy | Domain
ACLService           -> AuthorizationPolicy | Ports | Domain
AuthorizationPolicy  -> Ports | Domain
Ports                -> Domain
adapter impl         -> Ports | Domain
```

Gli adapter implementano porte e sono assemblati dal bootstrap. Nessun layer
interno conosce i dettagli di persistenza, protocolli, credenziali o identity
provider esterni.

---

## 7. Gestione ACL e prevenzione dell'escalation

La gestione delle entry e' essa stessa governata da ACL. Le regole sono:

1. **`MANAGE_ACL` non ereditabile.** Gestire la ACL di una risorsa e' un atto
   esplicito su quella risorsa o un privilegio globale.
2. **Chiave globale conservativa.** `MANAGE_ACL` su `SYSTEM:global` consente di
   gestire entry globali, radici di tipo e risorse concrete. Deve essere seminato
   solo al tier amministrativo di bootstrap o a gruppi equivalenti.
3. **Radici e sistema protetti.** `SYSTEM:global` e `<TYPE>:*` non sono gestibili
   tramite `MANAGE_ACL` ereditato o locale: richiedono sempre `MANAGE_ACL`
   globale.
4. **Profili fuori dal catalogo delegabile ordinario.** Assegnare livelli e
   gruppi richiede `MANAGE_PROFILES` o una policy amministrativa equivalente.
   Non deve essere ottenibile tramite `EDIT` dell'account, della persona o del
   profilo locale.
5. **Grant protetti.** Un soggetto con `MANAGE_ACL` su una risorsa non puo
   necessariamente concedere qualunque operazione. `GrantConstraintPolicy`
   applica regole come "non concedere operazioni che non possiedi", "non
   concedere `protected` senza autorizzazione globale" o "non concedere soglie
   piu privilegiate della propria".
6. **Claim esterni non autorevoli per default.** Claim OIDC come `groups`,
   `roles` o `acl_level` possono essere usati solo tramite mapping esplicito e
   allowlistato. L'IdP autentica l'identita; l'autorizzazione resta nel profilo
   autorevole del sistema.
7. **Input di richiesta non autorevole.** Plugin, estensioni e payload esterni non
   passano mai direttamente il subject effettivo: il subject arriva da
   `IdentityResolver`, normalizzatore di richiesta o registry affidabile.

---

## 8. Bootstrap e default

Il sistema nasce senza entry e in tale stato nega tutto. Il bootstrap crea uno
stato iniziale amministrabile senza introdurre bypass permanenti.

### 8.1 Stato iniziale

- nessuna entry ACL;
- nessun amministratore applicativo;
- ogni mutazione negata;
- un solo flusso o azione di setup bootstrap abilitata in modo controllato.

### 8.2 Gruppi iniziali

| Gruppo | Uso |
|--------|-----|
| `public` | Implicito per tutti; non e' una membership ordinaria. |
| `default` | Utenti standard abilitati a operazioni base, se il dominio lo desidera. |
| `admins` | Amministratori, alternativa o complemento al livello 0. |
| `service` | Service account, opzionale. |

### 8.3 Soglie di bootstrap

Valori consigliati:

```text
read_threshold  = 100
write_threshold = 50
admin_threshold = 0
```

Il bootstrap puo materializzare entry come:

| Ambito | Operazioni | Criterio |
|--------|------------|----------|
| `SYSTEM:global` | `MANAGE_ACL`, `MANAGE_PROFILES`, `MANAGE_ACCOUNTS`, `MANAGE_IDENTITIES` | livello `<= admin_threshold` o gruppo `admins` |
| `SYSTEM:global` | `CREATE_*`, `EXECUTE` | livello `<= write_threshold` o gruppo dedicato |
| `<TYPE>:*` | `VIEW`, `LIST` | livello `<= read_threshold` o gruppo `public` se la lettura deve essere pubblica |
| `<TYPE>:*` | `EDIT`, `DELETE`, operazioni operative | livello `<= write_threshold` |

Le soglie di configurazione servono solo a seminare il primo stato. Dopo il
bootstrap, le entry sono ordinarie e modificabili secondo le regole di gestione
ACL: radici e `SYSTEM:global` richiedono sempre `MANAGE_ACL` globale.

### 8.4 Primo amministratore

Il primo amministratore e' creato da un flusso di setup unico, non da una regola
ACL preesistente. Dopo la creazione:

- riceve livello `0` o gruppo amministrativo equivalente;
- soddisfa le entry di bootstrap su `SYSTEM:global`;
- puo gestire profili, radici e ACL globali.

In deployment OIDC-only, l'eventuale "primo login diventa admin" deve essere
esplicito in configurazione e vincolato da issuer, audience, subject, dominio
email o gruppo IdP allowlistato. Non deve dipendere ciecamente da claim non
verificati.

---

## 9. Riepilogo autorizzazioni per operazione

Esempi non normativi:

| Caso | Risorsa verificata | Operazione |
|------|--------------------|------------|
| Creare una risorsa globale | `SYSTEM:global` | `CREATE` o `CREATE_<TYPE>` |
| Creare un figlio delegabile | padre concreto | `CREATE_<CHILD>` o operazione specifica del dominio |
| Listare o vedere una risorsa | risorsa concreta, con fallback ai padri | `LIST`, `VIEW` |
| Modificare metadati | risorsa concreta, se ereditabile anche padri | `EDIT` o `EDIT_METADATA` |
| Eliminare | risorsa concreta | `DELETE` |
| Gestire entry di una risorsa | risorsa concreta, non ereditata | `MANAGE_ACL` |
| Gestire entry globali o radici | `SYSTEM:global` | `MANAGE_ACL` |
| Modificare livelli/gruppi | `SYSTEM:global` | `MANAGE_PROFILES` |
| Estensione non mappata read-only | `SYSTEM:global` | `VIEW` |
| Estensione non mappata mutante | `SYSTEM:global` | `EXECUTE` |

Regola trasversale: se non esiste una `ALLOW` matchante, o se esiste un `DENY`
matchante nel set decisivo, l'esito e' negato.

---

## 10. Considerazioni operative

### 10.1 Consistenza transazionale

Le mutazioni ACL dovrebbero vivere nella stessa unit of work della mutazione di
dominio che le richiede:

- creazione risorsa + seeding;
- eliminazione risorsa + `delete_by_resource`;
- eliminazione soggetto + `delete_by_subject` e rimozione membership.

Se lo stesso confine transazionale non e' possibile, il service deve prevedere
compensazioni esplicite e idempotenti.

### 10.2 Liste e performance

`candidate_resources` e' una pre-selezione, non una autorizzazione definitiva.
Ogni risultato esposto al chiamante va rifinito con `is_allowed`.

Per grandi volumi:

- preferire `list_by_operation(operation, resource_type)` indicizzata;
- batchare `entries_for` per insiemi di risorse;
- evitare N query ripetute sui padri comuni con cache per-richiesta;
- mantenere `AuthorizationPolicy` stateless: eventuali cache sono esterne o
  scoped alla singola richiesta.

### 10.3 Errori, audit e mapping

Errori consigliati:

| Errore | Significato | Esito di confine tipico |
|--------|-------------|-------------------------|
| `AuthenticationError` | identita richiesta ma assente/non valida | richiesta identita valida o avvia autenticazione esterna |
| `AuthorizationDenied` | identita valida ma accesso negato | nega senza rivelare dettagli interni |
| `ACLValidationError` | entry viola INV-1..INV-7 | segnala input non valido |
| `GrantConstraintError` | grant vietato da policy | nega o segnala grant non ammissibile |

Eventi minimi di audit:

- `AUTHZ_DENIED`;
- `ACL_ENTRY_CREATED`;
- `ACL_ENTRY_UPDATED`;
- `ACL_ENTRY_DELETED`;
- `PROFILE_CHANGED`;
- `BOOTSTRAP_COMPLETED`.

La traccia di una decisione puo essere salvata in audit, ma non deve essere
restituita a soggetti non autorizzati.

### 10.4 Default ergonomici dei normalizzatori

I normalizzatori di richiesta possono offrire default comodi, ma il service deve
sempre rivalidare:

- entry `USER` senza criteri -> suggerire soglia universale;
- entry `PUBLIC` senza criteri -> suggerire gruppo `public`;
- operazioni mutanti con `PUBLIC public` -> rifiutare per INV-2;
- input esterni non devono poter inviare subject arbitrari al posto
  dell'identita risolta.

---

## 11. Scelte architetturali e razionale

### 11.1 Entry a criteri componibili

Un'unica entry contiene identita, risorsa, operazione, verdetto e criteri di
profilo. Questo evita sottosistemi paralleli per ruoli, proprietari impliciti e
permessi globali.

### 11.2 INV-2 anti-anonimo

La regola "PUBLIC solo read-only" e' semplice ma troppo rigida: impedisce
concessioni mutanti a gruppi o livelli usando `PUBLIC` come assenza di vincolo
identitario. La forma anti-anonimo e' piu generale e mantiene la proprieta di
sicurezza essenziale: un richiedente anonimo non puo mutare.

### 11.3 Radici di tipo

`<TYPE>:*` consente default per categoria senza duplicare entry su ogni risorsa.
La valutazione resta una normale ereditarieta, mentre la gestione resta protetta
da `MANAGE_ACL` globale.

### 11.4 Nessuna ownership

Il creatore non ha un canale speciale. Se deve mantenere controllo, lo riceve
tramite entry seminate. Questo rende ogni privilegio visibile, revocabile e
soggetto a `DENY`.

### 11.5 Policy pura e facade applicativa

`AuthorizationPolicy` resta piccola e testabile; `AuthorizationService` e
`ACLService` traducono richieste normalizzate, identita, errori, DTO,
transazioni e autoprotezione. La separazione mantiene la single responsibility:
la policy decide, il service orchestra, gli adapter di richiesta parlano con il
mondo esterno.

### 11.6 Claim esterni non autorevoli

Separare identita e autorizzazione evita escalation tramite configurazioni IdP.
OIDC, LDAP o altri provider possono autenticare e fornire hint; la decisione
autorizzativa usa il profilo autorevole risolto da `ProfileProvider`.

---

## 12. Test architetturali minimi

| Area | Casi |
|------|------|
| Invarianti | INV-1..INV-7, inclusi `PUBLIC + subject_join=OR`, mutazioni anonime negate e grant protetti. |
| Match | livello, gruppo, join `AND/OR`, soglia universale, soggetto specifico e `PUBLIC`. |
| Risoluzione | `DENY` wins, default deny, entry proprie che chiudono la decisione. |
| Ereditarieta | padre singolo, multi-padre con `DENY` bloccante, default deny di un padre non bloccante, cicli, operazioni non ereditabili. |
| Sistema e radici | `SYSTEM:global`, `<TYPE>:*`, modifica solo con `MANAGE_ACL` globale. |
| Seeding | entry del creatore, revoca successiva, configurazioni per tipo, transazione/compensazione. |
| Candidate list | solo `ALLOW` candidate, rifinitura con `is_allowed`, applicazione dei `DENY`. |
| Profili | anonimo, gruppo `public`, gruppi multipli, profilo disabilitato -> anonimo, no self-escalation. |
| Enforcement | Richieste normalizzate, fallback conservativi, errori di confine e assenza di bypass del service. |
| Bootstrap | sistema vuoto deny-by-default, setup unico, primo admin, semina soglie e radici. |

---

## 13. Glossario

| Termine | Significato |
|---------|-------------|
| `ACLEntry` | Affermazione atomica di autorizzazione. |
| `SubjectRef` | Criterio identitario: `USER`, `PUBLIC`, opzionalmente `SERVICE`. |
| `ResourceRef` | Risorsa: `SYSTEM:global`, `<TYPE>:*` o `<TYPE>:<id>`. |
| `OperationSpec` | Metadati dell'operazione: `read_only`, `inheritable`, `protected`. |
| `Permission` | Verdetto `ALLOW` o `DENY`. |
| `Profile` | Livello e gruppi del richiedente, risolti a ogni richiesta. |
| `RequestIdentity` | Identita risolta per una richiesta, indipendente dal canale di origine. |
| `AuthorizationRequest` | Richiesta normalizzata con identita, operazione e risorsa. |
| `ANON_SENTINEL` | Livello massimo/meno privilegiato, usato dal profilo anonimo e come soglia universale. |
| `public` | Gruppo implicito universale. |
| `SYSTEM:global` | Ambito globale per operazioni non legate a una risorsa concreta. |
| `<TYPE>:*` | Radice di tipo per default di categoria. |
| `AuthorizationPolicy` | Policy pura che decide `ALLOWED` o `DENIED`. |
| `RequestNormalizer` | Componente di confine che normalizza un contesto di invocazione in richieste ACL. |
| `AuthorizationService` | Facade applicativa per `require`, liste candidate e trace su richieste normalizzate. |
| `ACLService` | Service applicativo che gestisce entry, seeding, bootstrap e cascade. |
| `GrantConstraintPolicy` | Policy che limita cosa puo essere concesso da chi gestisce ACL. |
| `SeedingPolicy` | Configurazione che materializza entry iniziali alla creazione risorsa. |
| `MANAGE_ACL` | Operazione protetta per gestire entry ACL. |
| `MANAGE_PROFILES` | Operazione protetta per modificare livelli e gruppi dei profili. |
