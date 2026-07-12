# Sistema ACL - Specifica Implementativa

## 1. Scopo

Questo documento traduce `design/DESIGN.md` in una specifica implementativa unica per
un sottosistema ACL riusabile. Il contenuto e' indipendente dai domini
applicativi: il package conosce solo soggetti, risorse, operazioni, profili,
entry ACL, policy di autorizzazione e adapter esterni.

In caso di dubbio prevale sempre `design/DESIGN.md`. Questa specifica rende operative
le sue decisioni, con particolare attenzione a:

- clean architecture e dipendenze verso il nucleo;
- responsabilita singole per policy, service, repository e adapter;
- decisione ACL pura, stateless e testabile;
- nessuna ownership implicita;
- seeding revocabile tramite entry ordinarie;
- `DENY > ALLOW > DENIED`;
- default deny;
- `PUBLIC` mutante mai soddisfacibile dall'anonimo;
- profili esterni non autorevoli senza mapping esplicito.

---

## 2. Decisioni implementative consolidate

- **Core ACL:** implementazione Python pura con dataclass, enum, value object e
  funzioni pure. Nessun framework di invocazione, ORM o libreria IdP nel core.
- **Motore decisionale:** `AuthorizationPolicy` valuta entry persistite,
  profilo corrente, catalogo operazioni e gerarchia risorse. Non mantiene stato
  globale.
- **Gestione entry:** `ACLService` e' l'unico punto di scrittura delle entry e
  applica invarianti, grant constraints, seeding e cascade.
- **Enforcement:** qualunque invocazione viene trasformata in
  `AuthorizationRequest` o `CandidateResourcesRequest` e passa dai service ACL.
- **Autoprotezione:** le richieste di gestione ACL, profili e grant protetti
  sono autoprotette dal service quando il service ha regole piu precise del
  normalizzatore di richiesta.
- **Profili:** `ProfileProvider` risolve il profilo ad ogni richiesta. Il
  profilo anonimo e' un valore ordinario, non un ramo speciale.
- **Claim esterni:** claim come gruppi, ruoli o livelli sono input non
  autorevoli. Possono aggiornare profili solo tramite policy deterministica,
  allowlistata e auditabile.
- **Librerie:** il core non usa librerie ACL esterne. Le librerie Python servono
  agli adapter: persistenza, config, credenziali, identity provider, audit,
  test.

Non va introdotto un enforcer ACL generico come dipendenza del core: il modello
richiede criteri di profilo componibili, ereditarieta con chiusura sulle entry
proprie, radici di tipo, grant constraints e seeding revocabile. Implementarlo
direttamente mantiene il comportamento leggibile, verificabile e allineato al
design.

---

## 3. Struttura del package

Layout raccomandato:

```text
acl/
  domain/
    __init__.py
    identifiers.py
    subjects.py
    resources.py
    operations.py
    profiles.py
    entries.py
    decisions.py
    matching.py
    invariants.py
    errors.py
  ports/
    __init__.py
    repositories.py
    identity.py
    profiles.py
    resources.py
    operations.py
    grants.py
    audit.py
    uow.py
  application/
    __init__.py
    authorization_policy.py
    authorization_service.py
    acl_service.py
    bootstrap_service.py
    dto.py
    mappers.py
  infrastructure/
    persistence/
      sqlalchemy.py
      memory.py
      file_json.py
    profiles/
      persisted.py
      claim_mapping.py
    config/
      settings.py
      loader.py
    audit/
      logging.py
  adapters/
    requests/
      context.py
      normalizer.py
      denied_mapper.py
    identity/
      resolver.py
      credentials.py
  bootstrap/
    container.py
    factory.py
```

Regole:

- `domain` non importa mai `ports`, `application`, `infrastructure`,
  framework, ORM o config runtime;
- `ports` definisce protocolli astratti e dipende solo da `domain`;
- `application` dipende da `domain` e `ports`;
- `infrastructure` implementa le porte;
- `adapters` traducono contesti di invocazione esterni in richieste applicative;
- `bootstrap` assembla le dipendenze con dependency injection esplicita.

Il package puo essere pubblicato come libreria autonoma. Gli adapter specifici
vanno dichiarati come extra opzionali, per esempio `acl[sql]`, `acl[redis]`,
`acl[identity]`, `acl[audit]`, `acl[test]`.

---

## 4. Domain

### 4.1 Identificatori

Gli identificatori sono value object immutabili o alias tipizzati. Il core non
impone UUID, interi o stringhe: normalizza tutto a stringa stabile ai confini.

```python
from dataclasses import dataclass
from typing import NewType

ACLEntryId = NewType("ACLEntryId", str)
SubjectId = NewType("SubjectId", str)
GroupId = NewType("GroupId", str)
OperationName = NewType("OperationName", str)

SYSTEM_TYPE = "SYSTEM"
SYSTEM_ID = "global"
TYPE_ROOT_ID = "*"
PUBLIC_GROUP = "public"
ANON_SENTINEL = 2**31 - 1
```

Il layer applicativo genera `ACLEntryId`. I repository non devono introdurre id
nascosti che rendano non deterministica la serializzazione o il confronto nei
test.

### 4.2 `SubjectRef`

```python
from dataclasses import dataclass
from enum import StrEnum

class SubjectType(StrEnum):
    USER = "USER"
    PUBLIC = "PUBLIC"
    SERVICE = "SERVICE"

@dataclass(frozen=True, slots=True)
class SubjectRef:
    type: SubjectType
    id: str | None = None

    @staticmethod
    def public() -> "SubjectRef":
        return SubjectRef(SubjectType.PUBLIC, None)
```

Invarianti locali:

- `PUBLIC` ha sempre `id is None`;
- `USER` e `SERVICE` richiedono `id` non vuoto;
- l'identita anonima risolta dal confine usa `SubjectRef.public()`;
- i service account possono usare `SERVICE`; se un consumatore non distingue
  soggetti macchina e umani, puo rappresentarli come `USER`.

### 4.3 `ResourceRef`

```python
@dataclass(frozen=True, slots=True, order=True)
class ResourceRef:
    type: str
    id: str

    @staticmethod
    def system() -> "ResourceRef":
        return ResourceRef(SYSTEM_TYPE, SYSTEM_ID)

    @staticmethod
    def type_root(resource_type: str) -> "ResourceRef":
        return ResourceRef(resource_type, TYPE_ROOT_ID)

    @property
    def is_system(self) -> bool:
        return self.type == SYSTEM_TYPE and self.id == SYSTEM_ID

    @property
    def is_type_root(self) -> bool:
        return self.id == TYPE_ROOT_ID
```

Regole:

- `ResourceRef.system()` rappresenta operazioni globali;
- `ResourceRef.type_root("X")` rappresenta il default di una categoria;
- una risorsa concreta ha `id` diverso da `"global"` e `"*"`;
- il domain non conosce tipi concreti;
- la gerarchia viene fornita da `ResourceHierarchyProvider`.

### 4.4 `OperationSpec`

```python
@dataclass(frozen=True, slots=True)
class OperationSpec:
    name: str
    read_only: bool
    inheritable: bool = True
    protected: bool = False
```

Catalogo minimo consigliato:

| Operazione | `read_only` | `inheritable` | `protected` |
|---|:---:|:---:|:---:|
| `LIST` | si | si | no |
| `VIEW` | si | si | no |
| `CREATE` / `CREATE_*` | no | dipende | no |
| `EDIT` / `EDIT_*` | no | si | no |
| `DELETE` | no | si | no |
| `ASSIGN` / `UPLOAD` / operative equivalenti | no | dipende | no |
| `MANAGE_ACL` | no | no | si |
| `MANAGE_PROFILES` | no | no | si |
| `MANAGE_IDENTITIES` / `MANAGE_ACCOUNTS` | no | no | si |
| `EXECUTE` | no | no | si |

Il catalogo e' aperto, ma ogni nome usato da un'entry o da un normalizzatore di
richiesta deve risolversi a una `OperationSpec`. Operazioni sconosciute
falliscono al confine con errore di configurazione o validazione, non con
fallback permissivo.

### 4.5 `Permission`, `JoinOp` e `Decision`

```python
class Permission(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"

class JoinOp(StrEnum):
    AND = "AND"
    OR = "OR"

class Decision(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"

@dataclass(frozen=True, slots=True)
class EvaluationResult:
    decision: Decision
    explicit_deny: bool = False
```

`Permission` e' il verdetto dichiarato dall'entry. `Decision` e' l'esito della
policy dopo match, precedenza ed ereditarieta. `EvaluationResult` e' un dettaglio
interno della policy: conserva se il `DENIED` deriva da un `DENY` matchante, dato
necessario per combinare in modo conservativo i padri multipli.

### 4.6 `Profile`

```python
@dataclass(frozen=True, slots=True)
class Profile:
    level: int
    groups: frozenset[str]
    version: int | None = None

    def __post_init__(self) -> None:
        normalized = frozenset(g for g in self.groups if g)
        object.__setattr__(self, "groups", normalized | {PUBLIC_GROUP})

    @staticmethod
    def anonymous() -> "Profile":
        return Profile(level=ANON_SENTINEL, groups=frozenset({PUBLIC_GROUP}))

    def stored_groups(self) -> frozenset[str]:
        return self.groups - {PUBLIC_GROUP}
```

Regole:

- numero piu basso significa profilo piu privilegiato;
- `profile.level <= entry.level` soddisfa il criterio di livello;
- ogni profilo include sempre `"public"`;
- `"public"` non e' una membership ordinaria;
- il profilo anonimo non appartiene ad altri gruppi;
- soggetto assente, disabilitato, non trovato o non verificabile produce
  `Profile.anonymous()`;
- `version` e' opzionale e serve per cache/revoca, non per la decisione pura.

### 4.7 `ACLEntry`

```python
@dataclass(frozen=True, slots=True)
class ACLEntry:
    id: ACLEntryId
    subject: SubjectRef
    resource: ResourceRef
    operation: str
    permission: Permission
    level: int | None = None
    group: str | None = None
    profile_join: JoinOp = JoinOp.OR
    subject_join: JoinOp = JoinOp.AND
```

Una entry esprime una singola affermazione: un soggetto, una risorsa, una
operazione, un verdetto e almeno un criterio di profilo.

I default ergonomici possono essere applicati dai mapper di input, non dal
costruttore domain:

- input `USER` senza criteri -> `level = ANON_SENTINEL`;
- input `PUBLIC` senza criteri -> `group = "public"`;
- `profile_join` omesso -> `OR`;
- `subject_join` omesso -> `AND`.

Il service deve comunque validare gli invarianti sull'entry risultante.

### 4.8 Match puro

Funzioni in `domain/matching.py`:

```python
def subject_matches(entry_subject: SubjectRef, subject: SubjectRef) -> bool:
    if entry_subject.type == SubjectType.PUBLIC:
        return True
    return entry_subject == subject

def profile_part_matches(entry: ACLEntry, profile: Profile) -> bool:
    parts: list[bool] = []
    if entry.level is not None:
        parts.append(profile.level <= entry.level)
    if entry.group is not None:
        parts.append(entry.group in profile.groups)
    if not parts:
        return False
    return all(parts) if entry.profile_join == JoinOp.AND else any(parts)

def entry_matches(entry: ACLEntry, subject: SubjectRef, profile: Profile) -> bool:
    subject_part = subject_matches(entry.subject, subject)
    profile_part = profile_part_matches(entry, profile)
    if entry.subject_join == JoinOp.AND:
        return subject_part and profile_part
    return subject_part or profile_part

def resolve(
    entries: Sequence[ACLEntry],
    subject: SubjectRef,
    profile: Profile,
) -> EvaluationResult:
    matching = [entry for entry in entries if entry_matches(entry, subject, profile)]
    if any(entry.permission == Permission.DENY for entry in matching):
        return EvaluationResult(Decision.DENIED, explicit_deny=True)
    if any(entry.permission == Permission.ALLOW for entry in matching):
        return EvaluationResult(Decision.ALLOWED)
    return EvaluationResult(Decision.DENIED)
```

Le funzioni sono deterministiche, non leggono repository e non producono log.
L'audit e la trace appartengono al layer applicativo.

### 4.9 Invarianti

`ACLEntryInvariants` riceve `OperationCatalog` per conoscere `read_only` e
`protected` dell'operazione.

- **INV-1:** `level is not None or group is not None`.
- **INV-2:** se `permission == ALLOW` e `operation.read_only is False`, l'entry
  non deve matchare `SubjectRef.public()` con `Profile.anonymous()`.
- **INV-3:** `level`, se presente, e' `int >= 0`; `group`, se presente, e'
  stringa non vuota normalizzata.
- **INV-4:** `profile_join` e `subject_join` sono membri di `JoinOp`.
- **INV-5:** `subject.type == PUBLIC and subject_join == OR` e' sempre vietato.
- **INV-6:** la modifica di entry su `SYSTEM:global` o `<TYPE>:*` e' ammessa
  solo se il chiamante ha `MANAGE_ACL` su `SYSTEM:global`.
- **INV-7:** entry `ALLOW` su operazioni `protected` devono passare da
  `GrantConstraintPolicy`.

INV-6 e INV-7 richiedono contesto del chiamante e quindi sono applicate da
`ACLService`, non solo dalla funzione strutturale.

---

## 5. Porte

### 5.1 `ACLEntryRepository`

```python
class ACLEntryRepository(Protocol):
    def entries_for(self, resource: ResourceRef, operation: str) -> list[ACLEntry]: ...
    def list_by_operation(self, operation: str, resource_type: str) -> list[ACLEntry]: ...
    def list_by_resource(self, resource: ResourceRef) -> list[ACLEntry]: ...
    def get(self, entry_id: ACLEntryId) -> ACLEntry | None: ...
    def save(self, entry: ACLEntry) -> None: ...
    def delete(self, entry_id: ACLEntryId) -> None: ...
    def replace_entries(self, resource: ResourceRef, entries: Sequence[ACLEntry]) -> None: ...
    def delete_by_resource(self, resource: ResourceRef) -> None: ...
    def delete_by_subject(self, subject: SubjectRef) -> None: ...
    def is_empty(self) -> bool: ...
```

Responsabilita:

- persistere e recuperare entry;
- ordinare i risultati in modo stabile, per trace e test;
- non decidere autorizzazioni;
- non applicare default ergonomici;
- non leggere identita corrente;
- non implementare cascade di dominio oltre ai metodi espliciti.

### 5.2 `IdentityResolver`

```python
@dataclass(frozen=True, slots=True)
class RequestIdentity:
    subject: SubjectRef
    authenticated: bool
    auth_method: str | None = None
    authz_version: int | None = None
    principal_id: str | None = None
    credential_ref: str | None = None

class IdentityResolver(Protocol):
    def resolve(self, context: object) -> RequestIdentity: ...
```

Gli adapter implementano questa porta per il contesto di invocazione scelto dal
consumatore. Il core ACL riceve gia' un `RequestIdentity`: non verifica
password, credenziali, firme, challenge o flussi di autenticazione.

### 5.3 `ProfileProvider`

```python
class ProfileProvider(Protocol):
    def profile_of(self, subject: SubjectRef) -> Profile: ...
```

Regole:

- ritorna `Profile.anonymous()` per `PUBLIC`, soggetti assenti, disabilitati o
  non trovati;
- aggiunge sempre il gruppo `public` tramite il value object;
- puo usare `version` per invalidare cache esterne;
- non importa claim esterni direttamente, salvo mapping esplicito e auditabile.

### 5.4 `ResourceHierarchyProvider`

```python
class ResourceHierarchyProvider(Protocol):
    def parents_of(self, resource: ResourceRef) -> list[ResourceRef]: ...
```

Regole:

- restituisce una lista finita e stabile;
- non ritorna il nodo stesso;
- puo includere `ResourceRef.type_root(resource.type)` come padre finale delle
  risorse concrete quando il consumatore vuole default di categoria;
- `SYSTEM:global` e radici di tipo non hanno padri, salvo scelta esplicita del
  consumatore;
- la policy applica comunque guardia anti-ciclo.

### 5.5 `OperationCatalog`

```python
class OperationCatalog(Protocol):
    def get(self, operation: str) -> OperationSpec: ...
    def require(self, operation: str) -> OperationSpec: ...
```

`get` puo restituire errore di dominio per operazione sconosciuta. `require` e'
la variante consigliata nei service: fallisce in modo esplicito e non permette
default permissivi.

### 5.6 `GrantConstraintPolicy`

```python
class GrantConstraintPolicy(Protocol):
    def validate_grant(
        self,
        grantor: RequestIdentity,
        grantor_profile: Profile,
        entry: ACLEntry,
        operation: OperationSpec,
    ) -> None: ...
```

Strategie consigliate, configurabili per deployment:

- un gestore ACL locale non concede operazioni che non possiede sulla stessa
  risorsa, salvo privilegio globale;
- operazioni `protected` richiedono `MANAGE_ACL` globale o una regola esplicita;
- una soglia di livello piu privilegiata della soglia del grantor richiede
  autorizzazione globale;
- gruppi non assegnabili o non conosciuti sono rifiutati;
- grant a `PUBLIC` su mutazioni resta soggetto a INV-2.

La policy non salva entry e non decide l'accesso ordinario: limita solo cosa un
chiamante puo concedere.

### 5.7 `UnitOfWork`

```python
class UnitOfWork(Protocol):
    def transaction(self) -> ContextManager[None]: ...
```

E' opzionale, ma raccomandata per:

- seeding nella stessa transazione della creazione risorsa;
- `replace_entries` atomico;
- eliminazione risorsa + `delete_by_resource`;
- eliminazione soggetto + `delete_by_subject`;
- bootstrap idempotente.

### 5.8 Audit

```python
class AuditLogger(Protocol):
    def append(self, event: AuditEvent) -> None: ...
```

Eventi minimi:

- `AUTHZ_DENIED`;
- `ACL_ENTRY_CREATED`;
- `ACL_ENTRY_UPDATED`;
- `ACL_ENTRY_DELETED`;
- `ACL_ENTRIES_REPLACED`;
- `PROFILE_CHANGED`;
- `BOOTSTRAP_COMPLETED`;
- `GRANT_REJECTED`.

L'audit non deve contenere segreti, credenziali, password o claim raw non
necessari.

---

## 6. Application

### 6.1 `AuthorizationPolicy`

`AuthorizationPolicy` e' la decisione ACL pura con dipendenze su porte astratte.

```python
@dataclass(frozen=True, slots=True)
class DecisionTrace:
    subject: SubjectRef
    profile: Profile
    operation: str
    resource: ResourceRef
    decision: Decision
    reason: str
    explicit_deny: bool = False
    matched_entry_ids: tuple[ACLEntryId, ...] = ()
    visited_resources: tuple[ResourceRef, ...] = ()

class AuthorizationPolicy:
    def __init__(
        self,
        entries: ACLEntryRepository,
        profiles: ProfileProvider,
        hierarchy: ResourceHierarchyProvider,
        operations: OperationCatalog,
    ) -> None: ...

    def is_allowed(
        self,
        subject: SubjectRef,
        operation: str,
        resource: ResourceRef,
    ) -> Decision: ...

    def candidate_resources(
        self,
        subject: SubjectRef,
        operation: str,
        resource_type: str,
    ) -> list[ResourceRef]: ...

    def explain(
        self,
        subject: SubjectRef,
        operation: str,
        resource: ResourceRef,
    ) -> DecisionTrace: ...
```

Algoritmo normativo:

```text
is_allowed(subject, operation, resource):
  spec = operations.require(operation)
  profile = profiles.profile_of(subject)
  return evaluate(resource, visited = empty).decision

evaluate(current, visited) -> EvaluationResult:
  if current in visited:
    return EvaluationResult(DENIED)

  own = entries.entries_for(current, operation)
  if own:
    return resolve(own, subject, profile)

  if not spec.inheritable:
    return EvaluationResult(DENIED)

  parents = hierarchy.parents_of(current)
  parent_results = []
  for parent in parents:
    parent_results.append(evaluate(parent, visited + current))

  if any(result.explicit_deny for result in parent_results):
    return EvaluationResult(DENIED, explicit_deny=True)

  if any(result.decision == ALLOWED for result in parent_results):
    return EvaluationResult(ALLOWED)

  return EvaluationResult(DENIED)
```

Dettagli obbligatori:

- l'operation spec si risolve una volta e governa tutta la catena;
- entry proprie per quella operazione chiudono la decisione, anche se nessuna
  matcha;
- `DENY` ha precedenza immediata nel set decisivo della risorsa valutata;
- con piu padri vale una OR non permissiva: ogni ramo padre deve essere valutato
  prima di concedere;
- un `DENY` matchante in qualunque ramo padre blocca le `ALLOW` degli altri
  padri;
- un default deny o una entry propria non matchante in un padre non blocca le
  `ALLOW` degli altri padri;
- operazioni non ereditabili, come `MANAGE_ACL`, non risalgono ai padri;
- la guardia anti-ciclo nega il ramo ciclico e registra la causa in trace;
- `candidate_resources` restituisce solo una pre-selezione di `ALLOW` matchanti
  per soggetto/profilo e tipo risorsa;
- `explain` e' solo per audit/debug amministrativo.

La policy non conosce protocolli, credenziali, esiti esterni, ORM o cache
globali. Cache per-richiesta possono essere introdotte con un wrapper scoped
alle porte, non come stato condiviso della policy.

### 6.2 `AuthorizationService`

Facade applicativa per richieste autorizzative normalizzate.

```python
from collections.abc import Mapping

@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    identity: RequestIdentity
    operation: str
    resource: ResourceRef
    metadata: Mapping[str, str] | None = None

@dataclass(frozen=True, slots=True)
class CandidateResourcesRequest:
    identity: RequestIdentity
    operation: str
    resource_type: str
    metadata: Mapping[str, str] | None = None

class AuthorizationService:
    def is_allowed(
        self,
        request: AuthorizationRequest,
    ) -> bool: ...

    def require(
        self,
        request: AuthorizationRequest,
    ) -> None: ...

    def candidate_resources(
        self,
        request: CandidateResourcesRequest,
    ) -> list[ResourceRef]: ...

    def explain(
        self,
        request: AuthorizationRequest,
    ) -> DecisionTrace: ...
```

Responsabilita:

- ricevere solo richieste gia normalizzate dal confine;
- tradurre `request.identity` in `SubjectRef`;
- invocare la policy con `operation` e `resource` della richiesta;
- convertire `DENIED` in `AuthorizationDenied`;
- produrre audit dei dinieghi se configurato;
- delegare `candidate_resources` alla policy per liste ottimizzate;
- non salvare entry e non modificare profili;
- non interpretare il canale che ha originato la richiesta.

`candidate_resources`:

1. risolve il profilo del soggetto;
2. carica entry `ALLOW` con `list_by_operation(request.operation, request.resource_type)`;
3. filtra solo entry matchanti;
4. deduplica e ordina le risorse;
5. richiede al chiamante di rifinire ogni risorsa con `is_allowed`.

Il risultato non e' autorizzazione definitiva: non applica `DENY` di set
decisivi diversi, `DENY` ereditati da altri rami padre, entry proprie non
matchanti, ereditarieta completa o filtri di dominio.

### 6.3 `ACLService`

`ACLService` gestisce entry, non decide l'accesso ordinario.

```python
class ACLService:
    def list_entries(
        self,
        identity: RequestIdentity,
        resource: ResourceRef,
    ) -> list[ACLEntryDTO]: ...

    def create_entry(
        self,
        identity: RequestIdentity,
        input: ACLEntryInput,
    ) -> ACLEntryDTO: ...

    def update_entry(
        self,
        identity: RequestIdentity,
        entry_id: ACLEntryId,
        patch: ACLEntryPatch,
    ) -> ACLEntryDTO: ...

    def delete_entry(
        self,
        identity: RequestIdentity,
        entry_id: ACLEntryId,
    ) -> None: ...

    def replace_entries(
        self,
        identity: RequestIdentity,
        resource: ResourceRef,
        inputs: Sequence[ACLEntryInput],
    ) -> None: ...

    def delete_by_resource(self, resource: ResourceRef) -> None: ...
    def delete_by_subject(self, subject: SubjectRef) -> None: ...
    def on_resource_created(
        self,
        resource: ResourceRef,
        creator: SubjectRef,
        resource_type: str,
    ) -> None: ...
```

Responsabilita:

- applicare default ergonomici sugli input;
- validare INV-1..INV-7 prima della persistenza;
- richiedere `MANAGE_ACL` sulla risorsa concreta oppure su `SYSTEM:global`;
- richiedere sempre `MANAGE_ACL` su `SYSTEM:global` per entry su
  `SYSTEM:global` o `<TYPE>:*`;
- invocare `GrantConstraintPolicy` per `ALLOW` su operazioni `protected`;
- garantire che `replace_entries` sia atomico;
- verificare che update/delete agiscano su entry esistenti e coerenti;
- applicare seeding e cascade tramite hook interni;
- produrre audit di mutazioni e grant rifiutati.

I metodi `delete_by_resource`, `delete_by_subject` e `on_resource_created` sono
hook di ciclo vita interni. Non sono endpoint amministrativi e possono essere
invocati solo da casi d'uso gia autorizzati o dal bootstrap.

Ordine consigliato per `create_entry`:

1. risolvi operation spec;
2. costruisci `ACLEntry` da input normalizzato;
3. calcola il gate di gestione (`MANAGE_ACL` locale o globale);
4. applica la regola speciale per `SYSTEM:global` e radici;
5. valida invarianti strutturali;
6. invoca `GrantConstraintPolicy` se necessario;
7. salva in transazione;
8. emetti audit.

### 6.4 `BootstrapService`

```python
class BootstrapService:
    def ensure_bootstrap_entries(self, config: BootstrapACLConfig) -> None: ...
    def create_initial_admin(self, input: InitialAdminInput) -> SubjectRef: ...
```

Regole:

- il sistema vuoto nega tutto;
- il setup iniziale e' un flusso controllato e separato dall'ACL ordinaria;
- il primo amministratore riceve livello `0` o gruppo amministrativo
  equivalente;
- le entry bootstrap sono entry ordinarie;
- bootstrap e' idempotente e non sovrascrive entry modificate;
- l'eventuale first-admin da IdP esterno richiede flag esplicito e vincoli su
  issuer, audience, subject, dominio email o gruppo esterno allowlistato.

Entry consigliate:

- `SYSTEM:global`, operazioni amministrative (`MANAGE_ACL`,
  `MANAGE_PROFILES`, `MANAGE_IDENTITIES`, `MANAGE_ACCOUNTS`): criterio
  `level <= admin_threshold` o gruppo amministrativo.
- `SYSTEM:global`, operazioni globali (`CREATE_*`, `EXECUTE`): criterio
  `level <= write_threshold` o gruppo dedicato.
- `<TYPE>:*`, letture (`LIST`, `VIEW`): criterio `level <= read_threshold` o
  `group = public` se la lettura deve essere pubblica.
- `<TYPE>:*`, mutazioni operative (`EDIT`, `DELETE` e analoghe): criterio
  `level <= write_threshold`.

Valori default:

```text
read_threshold  = 100
write_threshold = 50
admin_threshold = 0
```

### 6.5 `SeedingPolicy`

```python
@dataclass(frozen=True, slots=True)
class SeedRule:
    resource_type: str
    operations: frozenset[str]
    grant_to: str = "CREATOR"
    level_strategy: str = "UNIVERSAL"

@dataclass(frozen=True, slots=True)
class SeedingPolicy:
    enabled: bool
    rules: Mapping[str, SeedRule]
```

Forma default per il creatore:

```text
ALLOW <operation>
  subject      = USER(creator)
  level        = ANON_SENTINEL
  subject_join = AND
```

Linee guida:

- risorse private possono seminare `VIEW`, `EDIT`, `DELETE`, `MANAGE_ACL`;
- risorse che ereditano visibilita dal padre seminano solo mutazioni operative e
  `MANAGE_ACL`;
- risorse governate da default globali possono seminare solo `MANAGE_ACL` o
  nulla;
- il seeding avviene nella stessa transazione della creazione risorsa;
- se non c'e' transazione condivisa, il caso d'uso deve avere compensazione
  idempotente;
- le entry seminate sono revocabili e soggette a `DENY`.

---

## 7. Persistenza

### 7.1 Schema SQL

Tabella raccomandata `acl_entries`:

| Colonna | Tipo | Note |
|---|---|---|
| `id` | string/uuid | primary key, generato dal layer applicativo |
| `subject_type` | string | `USER`, `PUBLIC`, `SERVICE` |
| `subject_id` | string nullable | null solo per `PUBLIC` |
| `resource_type` | string | `SYSTEM` o tipo registrato |
| `resource_id` | string | `global`, `*` o id concreto |
| `operation` | string | nome canonico uppercase |
| `permission` | string | `ALLOW` o `DENY` |
| `level` | integer nullable | `>= 0` |
| `group_id` | string nullable | non vuoto |
| `profile_join` | string | `AND` o `OR` |
| `subject_join` | string | `AND` o `OR` |
| `created_at` | datetime | audit tecnico |
| `updated_at` | datetime | audit tecnico |

Indici:

- `(resource_type, resource_id, operation)`;
- `(operation, resource_type)`;
- `(subject_type, subject_id)`;
- `(group_id)`;
- opzionale `(resource_type, operation, permission)` per liste candidate.

Vincoli:

- check su enum testuali;
- check `level >= 0`;
- check `subject_type = 'PUBLIC'` implica `subject_id IS NULL`;
- check `subject_type <> 'PUBLIC'` implica `subject_id IS NOT NULL`;
- check almeno uno tra `level` e `group_id`;
- check `subject_type <> 'PUBLIC' OR subject_join <> 'OR'`.

INV-2 e INV-7 dipendono dal catalogo operazioni e restano nel service.

### 7.2 Adapter SQLAlchemy

`SqlAlchemyACLEntryRepository`:

- usa SQLAlchemy 2.x;
- espone solo dataclass domain;
- mappa righe e value object in funzioni dedicate;
- non propaga modelli ORM fuori da `infrastructure`;
- usa transazioni dal `UnitOfWork`;
- non apre transazioni nascoste se una UoW e' gia attiva.

Migrazioni:

- Alembic crea schema e indici;
- ogni nuova colonna deve avere migrazione forward;
- downgrade e' consigliato per dev/test, ma non deve indebolire vincoli di
  sicurezza in produzione senza procedura esplicita.

### 7.3 Adapter in memoria e file

L'adapter in memoria serve a test unitari e demo. Non e' adatto a produzione.

L'adapter JSON file puo essere utile per prototipi o deployment single-user:

- persiste una entry per file o un file compatto append-safe;
- scrive con file temporaneo + rename atomico;
- mantiene indici rigenerabili;
- non va usato con writer concorrenti senza lock di processo.

---

## 8. Adapter di richiesta

Gli adapter di richiesta sono il bordo interfaccia-agnostico del package. Il loro
compito e' trasformare un contesto di invocazione, qualunque sia l'origine, in
DTO applicativi ACL.

### 8.1 Mapping di richiesta

Ogni adapter mantiene una mappa esplicita e versionabile:

```python
@dataclass(frozen=True, slots=True)
class RequestMappingRule:
    selector: str
    operation: str
    resource_type: str | None = None
    resource_id_source: str | None = None
    service_enforced: bool = False
    fallback_protected: bool = False
```

Risoluzione risorsa:

- `resource_type is None` -> `SYSTEM:global`;
- `resource_id_source is None` -> `<TYPE>:*`;
- altrimenti -> `<TYPE>:<resolved_id>` usando solo sorgenti affidabili del
  contesto di invocazione.

Richieste non mappate o ambigue:

- falliscono chiuso con `ResourceMappingError` o errore equivalente;
- possono usare un fallback conservativo solo se configurato esplicitamente;
- il fallback conservativo deve richiedere una operazione protetta o globale,
  mai concedere accesso per default.

Contratto del normalizzatore:

```python
class RequestNormalizer(Protocol):
    def authorization_request(
        self,
        context: object,
        identity: RequestIdentity,
    ) -> AuthorizationRequest: ...

    def candidate_resources_request(
        self,
        context: object,
        identity: RequestIdentity,
    ) -> CandidateResourcesRequest: ...
```

### 8.2 Pipeline di normalizzazione

Flusso raccomandato:

1. acquisisci `InvocationContext` dal runtime consumatore;
2. invoca `IdentityResolver.resolve(context)`;
3. invoca `RequestNormalizer.authorization_request(context, identity)` oppure
   `candidate_resources_request`;
4. per richieste ordinarie chiama `AuthorizationService.require(request)`;
5. per gestione ACL chiama `ACLService`, passando l'identita risolta e gli input
   validati;
6. mappa eventuali errori applicativi con `DeniedResponseMapper` o componente
   equivalente del consumatore.

Il normalizzatore non deve fidarsi di campi arbitrari forniti dal chiamante. Se
un campo esterno serve a selezionare una risorsa, deve passare da validazione,
canonicalizzazione e binding al dominio consumatore.

### 8.3 `DeniedResponseMapper`

Il core ACL produce errori applicativi, non rappresentazioni di protocollo.

```python
class DeniedResponseMapper(Protocol):
    def map_error(self, error: ACLError, context: object) -> object: ...
```

Regole:

- `AuthenticationRequired` indica che manca una identita valida dove richiesta;
- `AuthorizationDenied` indica identita valida ma non autorizzata;
- `ACLValidationError` e `GrantConstraintError` non devono diventare errori
  interni generici;
- `DecisionTrace` dettagliate sono visibili solo a richieste amministrative
  autorizzate;
- il mapper puo scegliere l'esito esterno piu adatto al runtime chiamante, ma
  non puo trasformare un diniego in successo.

### 8.4 Richieste autoprotette dal service

Alcuni flussi devono passare dal service specifico invece che dal solo gate
ordinario:

- gestione di entry ACL;
- modifica di profili e gruppi;
- concessione di operazioni `protected`;
- bootstrap e seeding;
- cascade di risorse o soggetti.

`RequestMappingRule.service_enforced = True` segnala che il normalizzatore deve
produrre input per il service applicativo competente. Il service rivalida sempre
invarianti, grant constraints e autorizzazioni interne: il mapping di richiesta
non e' una fonte di autorizzazione.

### 8.5 Anti-bypass

Qualunque helper, binding o facade del consumatore deve passare da
`AuthorizationService` o dal service autoprotetto. Sono vietati accessi diretti
ai casi d'uso protetti quando il controllo ACL e' richiesto.

---

## 9. Profilo e integrazione identita

### 9.1 Profilo autorevole

Il profilo autorevole e' persistito o calcolato da una fonte controllata dal
consumatore. L'IdP esterno autentica, ma non autorizza automaticamente.

Implementazione raccomandata:

- `PersistedProfileProvider` legge livello e gruppi da repository locale;
- `ExternalClaimMappingPolicy`, se abilitata, converte claim esterni in proposte
  di aggiornamento;
- il mapping e' allowlistato per issuer/audience/provider;
- ogni aggiornamento profilo produce audit;
- gruppi rimossi dall'origine esterna non diventano `DENY`: vengono rimossi dal
  profilo e la decisione torna al default deny.

### 9.2 Modifica profili

La modifica di `level` e `groups` non e' un normale `EDIT` dell'account o del
profilo utente. Deve passare da un service amministrativo protetto da
`MANAGE_PROFILES SYSTEM:global` o da policy equivalente piu restrittiva.

Regole:

- un soggetto non puo auto-elevarsi;
- ridurre numericamente un livello e' escalation;
- aggiungere gruppi privilegiati e' escalation;
- le modifiche incrementano `Profile.version` se disponibile;
- cache e credenziali esterne possono essere invalidate confrontando
  `authz_version`.

---

## 10. Configurazione

Esempio:

```yaml
acl:
  read_threshold: 100
  write_threshold: 50
  admin_threshold: 0
  seeding_enabled: true

  operations:
    LIST:
      read_only: true
      inheritable: true
      protected: false
    VIEW:
      read_only: true
      inheritable: true
      protected: false
    EDIT:
      read_only: false
      inheritable: true
      protected: false
    DELETE:
      read_only: false
      inheritable: true
      protected: false
    MANAGE_ACL:
      read_only: false
      inheritable: false
      protected: true
    MANAGE_PROFILES:
      read_only: false
      inheritable: false
      protected: true
    EXECUTE:
      read_only: false
      inheritable: false
      protected: true

  resource_roots:
    - DOCUMENT
    - COLLECTION

  seeding:
    DOCUMENT:
      operations: [VIEW, EDIT, DELETE, MANAGE_ACL]
    COLLECTION:
      operations: [MANAGE_ACL]
```

Priorita:

```text
secret manager / env > file config > default sicuri
```

Regole:

- il loader infrastrutturale converte YAML/TOML/JSON/env in settings tipizzati;
- il domain non importa il loader;
- ogni operazione configurata viene validata al bootstrap;
- `MANAGE_ACL` deve essere non ereditabile e protetta;
- `MANAGE_PROFILES` deve essere separata da `EDIT`;
- configurazioni che rendono anonime mutazioni possibili falliscono al
  bootstrap;
- backend opzionali dichiarati ma senza dipendenza installata falliscono al
  bootstrap con errore chiaro.

---

## 11. Librerie Python consigliate

Verifica licenze effettuata al 2026-07-09 su metadata PyPI/progetto. Le versioni
vanno fissate nel lock file del consumatore e riverificate prima del rilascio.

Target consigliato: Python 3.12+. Minimo pratico: Python 3.10+, per allinearsi
alle librerie moderne di config, storage, identita e test.

- **Core domain/application:** standard library (`dataclasses`, `enum`,
  `typing`, `uuid`, `datetime`, `contextlib`), licenza PSF. Serve a value
  object, policy pure, protocolli e UoW astratta.
- **Config e DTO di confine:** `pydantic`, `pydantic-settings`, licenza MIT.
  Servono a settings, env mapping e validazione degli input di confine. Non
  usarli per entita domain.
- **SQL e migrazioni:** `SQLAlchemy`, `Alembic`, licenza MIT. Servono a
  repository SQL e migrazioni, con ORM confinato in infrastructure.
- **Driver SQL opzionali:** `aiosqlite` (MIT), `asyncpg` (Apache-2.0),
  `PyMySQL` (MIT). Servono a SQLite dev/test, PostgreSQL e MySQL/MariaDB.
- **Store condiviso:** `redis`, licenza MIT. Serve a cache per-richiesta
  distribuita, revoche e rate limit quando il consumatore lo richiede.
- **Credenziali e chiavi:** `PyJWT[crypto]` (MIT), `cryptography`
  (Apache-2.0 OR BSD-3-Clause). Servono a verifica di credenziali firmate,
  JWK/PEM e firme, solo negli identity adapter.
- **Provider identita esterni:** `Authlib`, `httpx`, licenza BSD-3-Clause.
  Servono a discovery, JWKS e chiamate di rete con timeout verso provider
  identita esterni.
- **Password se il consumatore include autenticazione locale:** `argon2-cffi`
  (MIT), `bcrypt` (Apache-2.0). Argon2id e' il default; bcrypt resta per
  compatibilita e migrazione. Fuori dal core ACL.
- **Rate limit:** `limits`, licenza MIT. Serve a limiti su Redis, Memcached o
  altri storage supportati negli adapter.
- **Audit logging:** `structlog` (MIT OR Apache-2.0) oppure `logging` stdlib
  (PSF). Servono a eventi strutturati senza segreti.
- **Test:** `pytest`, licenza MIT. Serve a test unitari, integrazione e
  regression suite.
- **YAML/TOML config:** `PyYAML`, `tomli-w`, licenza MIT. Servono a loader
  infrastrutturali opzionali.

Regole di adozione:

- nessuna dipendenza esterna entra in `domain`;
- `application` usa solo standard library e porte;
- ogni libreria e' confinata all'adapter che la richiede;
- evitare dipendenze GPL/AGPL nello stack predefinito;
- ogni extra opzionale dichiara licenza, motivo e layer di appartenenza;
- le dipendenze crypto e identity-provider devono avere versioni fissate e
  update policy.

---

## 12. Errori e mapping

Gerarchia consigliata:

```python
class ACLError(Exception): ...
class AuthenticationRequired(ACLError): ...
class AuthorizationDenied(ACLError): ...
class ACLValidationError(ACLError): ...
class GrantConstraintError(ACLError): ...
class OperationUnknownError(ACLError): ...
class ResourceMappingError(ACLError): ...
```

Mapping tipico:

| Errore | Categoria | Regola di confine |
|---|---|---|
| `AuthenticationRequired` | identita assente/non valida | richiede una identita valida tramite il runtime chiamante |
| `AuthorizationDenied` | accesso negato | nega senza rivelare struttura ACL interna |
| `ACLValidationError` | input ACL non valido | segnala validazione fallita |
| `GrantConstraintError` | grant vietato | segnala grant non ammissibile o nega la richiesta |
| `OperationUnknownError` | catalogo o input non valido | fallisce chiuso, distinguendo errore config da input esterno |
| `ResourceMappingError` | richiesta non mappabile | fallisce chiuso o applica fallback conservativo configurato |

Gli adapter non devono trasformare `AuthorizationDenied` in successo o in errore
interno generico. Le trace dettagliate non vanno esposte a soggetti non
autorizzati.

---

## 13. Pattern applicati

| Pattern | Uso |
|---|---|
| Ports and Adapters | Isola domain/application da persistenza, credenziali, identity provider e config. |
| Repository | Incapsula query e persistenza di `ACLEntry`. |
| Unit of Work | Garantisce transazioni per seeding, replace, cascade e bootstrap. |
| Strategy | `GrantConstraintPolicy`, `SeedingPolicy`, mapping dei claim esterni, gerarchia risorse. |
| Facade | `AuthorizationService` espone API semplice per richieste normalizzate. |
| Specification | `OperationSpec` e invarianti rendono esplicite le regole di validazione. |
| Factory/Composition Root | `bootstrap/factory.py` assembla implementazioni concrete senza dipendenze inverse. |
| Boundary Guard | Helper e binding del consumatore applicano `require` senza duplicare logica nei casi d'uso. |

Regola SRP:

- `AuthorizationPolicy` decide;
- `AuthorizationService` orchestra richieste di autorizzazione normalizzate;
- `ACLService` gestisce entry;
- `ProfileProvider` risolve profili;
- `ResourceHierarchyProvider` risolve padri;
- `OperationCatalog` descrive operazioni;
- repository persistono;
- adapter traducono contesti di invocazione.

---

## 14. Test minimi

### 14.1 Unit test domain

- `SubjectRef` valido/non valido;
- `ResourceRef.system`, `type_root`, risorse concrete;
- `Profile` aggiunge `public`;
- `Profile.anonymous`;
- match per soggetto specifico;
- match `PUBLIC`;
- match livello con orientamento numerico;
- match gruppo;
- `profile_join` `AND` e `OR`;
- `subject_join` `AND` e `OR`;
- `PUBLIC + subject_join=OR` rifiutato;
- `DENY > ALLOW`;
- default deny.

### 14.2 Invarianti

- INV-1 entry senza criteri rifiutata;
- INV-2 mutazione anonima rifiutata;
- INV-2 mutazione `PUBLIC group=editors` accettata se anonimo non matcha;
- INV-3 livello negativo e gruppo vuoto rifiutati;
- INV-4 join invalidi rifiutati al parsing;
- INV-5 `PUBLIC OR` rifiutato;
- INV-6 radici e sistema richiedono `MANAGE_ACL` globale;
- INV-7 grant protetto passa da `GrantConstraintPolicy`.

### 14.3 Policy

- entry proprie chiudono la decisione;
- entry proprie non matchanti impediscono ereditarieta;
- ereditarieta padre singolo;
- ereditarieta multi-padre con `DENY` bloccante;
- default deny di un padre non blocca `ALLOW` su altro padre;
- `DENY` matchante su un padre blocca `ALLOW` su altro padre;
- ciclo gerarchico negato senza ricorsione infinita;
- operazione non ereditabile;
- `SYSTEM:global`;
- `<TYPE>:*`;
- trace non contiene segreti.

### 14.4 Service

- `create_entry` richiede `MANAGE_ACL`;
- `replace_entries` e' atomico;
- update valida l'entry risultante;
- delete controlla appartenenza e autorizzazione;
- `delete_by_resource` e `delete_by_subject` sono idempotenti;
- seeding crea entry ordinarie;
- revoca di entry seminata rimuove il privilegio;
- bootstrap su repository vuoto;
- bootstrap non sovrascrive entry esistenti;
- grant protetto rifiutato produce audit.

### 14.5 Adapter

- `RequestNormalizer` produce `AuthorizationRequest` corretta;
- richieste non mappate o ambigue falliscono chiuso;
- fallback conservativo -> operazione protetta su `SYSTEM:global`;
- identita assente produce `RequestIdentity` anonima o errore esplicito secondo
  configurazione;
- identita valida ma negata diventa `AuthorizationDenied`;
- `DeniedResponseMapper` non trasforma dinieghi in successi;
- richieste autoprotette passano dal service applicativo competente;
- helper e binding del consumatore non bypassano `AuthorizationService`.

### 14.6 Integrazione librerie

- SQLAlchemy: vincoli, indici, transazioni, migrazioni Alembic da schema vuoto;
- Redis: TTL e namespace per revoche/cache/rate limit;
- PyJWT/cryptography: issuer/audience, `kid`, algoritmi allowlistati, revoca;
- Authlib/httpx: timeout, verifica TLS, discovery fallita, JWKS refresh;
- Pydantic: env mapping e config insicure rifiutate;
- pytest: fixture isolate e repository in memoria deterministico.

---

## 15. Checklist di aderenza a `design/DESIGN.md`

- Autenticazione e autorizzazione restano separate.
- Ogni decisione deriva da `ACLEntry` persistite.
- Soggetto, livello e gruppo sono criteri indipendenti e componibili.
- Operazione e permesso restano distinti.
- Numero di livello piu basso significa profilo piu privilegiato.
- `PUBLIC` non equivale automaticamente ad anonimo autorizzato.
- Il profilo anonimo e' `Profile(ANON_SENTINEL, {"public"})`.
- `DENY` prevale su `ALLOW`; assenza di `ALLOW` significa `DENIED`.
- Entry proprie chiudono la decisione per operazione.
- Ereditarieta e' figlio -> padre, con OR non permissiva tra padri: qualunque
  `DENY` matchante in un ramo padre blocca le concessioni degli altri rami.
- `MANAGE_ACL` non eredita.
- `SYSTEM:global` e `<TYPE>:*` richiedono `MANAGE_ACL` globale per gestione.
- Non esiste ownership implicita o fast-path proprietario.
- Il creatore riceve privilegi solo via seeding revocabile.
- `MANAGE_PROFILES` e' separato da `EDIT`.
- Claim esterni non sono autorevoli per default.
- `AuthorizationPolicy` e' pura e stateless.
- `AuthorizationService` e' la facade per richieste normalizzate.
- `ACLService` e' l'unico punto di scrittura ACL.
- `GrantConstraintPolicy` governa i grant protetti.
- Qualunque invocazione passa dal confine di normalizzazione richieste.
- `RequestNormalizer` fallisce chiuso su richieste non mappabili o ambigue.
- `candidate_resources` e' solo preselezione e viene rifinito con `is_allowed`.
- Test minimi coprono INV-1..INV-7, match, ereditarieta, bootstrap e adapter.

---

## 16. Criteri di accettazione per una prima implementazione

Una prima versione e' completa quando include:

1. package layout con `domain`, `ports`, `application`, `infrastructure`,
   `adapters` e `bootstrap`;
2. dataclass domain immutabili e funzioni pure di match/resolve;
3. `ACLEntryInvariants` con INV-1..INV-5 strutturali;
4. `AuthorizationPolicy` con ereditarieta, guardia anti-ciclo, trace e
   `candidate_resources`;
5. `AuthorizationService` con `require` e wrapping di `candidate_resources`;
6. `ACLService` con CRUD, replace atomico, INV-6, INV-7, seeding e cascade;
7. `OperationCatalog` configurabile e validato al bootstrap;
8. almeno un repository in memoria per test e uno SQL per produzione;
9. adapter di richiesta minimi con `RequestNormalizer`, `IdentityResolver` e
   `DeniedResponseMapper`;
10. bootstrap con entry iniziali e seeding configurabile;
11. suite pytest sulle aree del capitolo 14;
12. documentazione degli extra Python e delle licenze.

---

## 17. Diagrammi implementativi

I diagrammi PlantUML relativi a questa specifica vivono sotto
`implementation/`:

- `00_mappa_implementazione.puml`: indice generale dei diagrammi implementativi;
- `use case/`: casi d'uso del package ACL e dei suoi adapter di richiesta;
- `componenti/`: package, layer, porte, adapter, persistenza, config e audit;
- `classi/`: dataclass, enum, service, policy, porte e schema di persistenza;
- `attivita/`: flussi operativi di normalizzazione, autorizzazione, policy,
  CRUD ACL, bootstrap e liste candidate;
- `oggetti/`: istanze esemplari di request, entry, seeding, multi-padre e row
  SQL.
