<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Sistema ACL

![Licenza: CC BY-SA 4.0](https://img.shields.io/badge/licenza-CC%20BY--SA%204.0-lightgrey.svg)

Questo repository raccoglie la specifica progettuale e implementativa di un
sottosistema ACL riusabile. L'obiettivo è descrivere un modello di
autorizzazione dichiarativo, default-deny e indipendente dai domini applicativi:
le applicazioni consumatrici forniscono identità, catalogo operazioni,
gerarchia risorse, persistenza e adapter di integrazione.

Il nucleo concettuale ruota attorno ad `ACLEntry`, `SubjectRef`, `ResourceRef`,
`Profile`, `Permission` e alle regole decisionali documentate in
[design/DESIGN.md](design/DESIGN.md). La specifica implementativa traduce queste
decisioni in un layout Python raccomandato, con separazione tra domain, ports,
application, infrastructure, adapters e bootstrap.

## Stato del progetto

Il checkout contiene la specifica progettuale, la specifica implementativa, i
diagrammi PlantUML di supporto, una prima implementazione Python e una suite di
test. La struttura corrente è:

```text
src/             codice di produzione
tests/           test automatici
design/          specifica progettuale e diagrammi
implementation/  specifica implementativa e diagrammi
```

Il package ACL a layer descritto in
[implementation/IMPLEMENTATION.md](implementation/IMPLEMENTATION.md) (§3) vive
direttamente sotto `src/`: i package top-level `domain`, `ports`,
`application`, `infrastructure`, `adapters` e `bootstrap` sono la struttura
interna autorevole del sottosistema.

## Struttura

- [design/DESIGN.md](design/DESIGN.md): documento architetturale di
  riferimento per modello ACL, decisioni, invarianti, policy e confini.
- [design/](design/): diagrammi PlantUML progettuali per use case, componenti,
  classi, oggetti e attività.
- [implementation/IMPLEMENTATION.md](implementation/IMPLEMENTATION.md):
  specifica implementativa per package layout, responsabilità dei layer, porte,
  servizi e adapter.
- [implementation/](implementation/): diagrammi PlantUML implementativi per
  pipeline, oggetti, attività, componenti e mapping di persistenza.

Mappe principali:

- [design/00_mappa_architettura.puml](design/00_mappa_architettura.puml)
- [implementation/00_mappa_implementazione.puml](implementation/00_mappa_implementazione.puml)

## Principi

- Autorizzazione basata su entry persistite.
- Separazione tra autenticazione e autorizzazione.
- Decisione pura, stateless e testabile.
- Precedenza conservativa `DENY > ALLOW > DENIED`.
- Default deny in assenza di concessioni esplicite.
- Nessuna ownership implicita: i privilegi iniziali derivano da seeding di entry
  ordinarie, revocabili e ispezionabili.
- `PUBLIC` e profilo anonimo trattati come casi ordinari, con divieto di
  concessioni mutanti soddisfacibili dall'anonimo.

## Controlli consigliati

Prima di inviare modifiche, eseguire la suite e i controlli leggeri sulla
documentazione:

```sh
python -m compileall -q src tests
python -m pytest
rg -n "INV-|D[0-9]" design/DESIGN.md
find design implementation -name '*.puml' -print
markdownlint README.md design/DESIGN.md implementation/IMPLEMENTATION.md
git diff --check
```

`markdownlint` è opzionale: eseguirlo solo se disponibile nell'ambiente.

## Licenza

Salvo diversa indicazione, i contenuti di questo repository sono distribuiti con
licenza **Creative Commons Attribution-ShareAlike 4.0 International**
(`CC BY-SA 4.0`).

Identificativo SPDX:

```text
CC-BY-SA-4.0
```

Attribuzione consigliata:

```text
Sistema ACL, Francesco, licenza Creative Commons Attribution-ShareAlike 4.0 International.
```

Quando riusi o adatti il materiale, conserva il riferimento alla licenza,
attribuisci la fonte, indica eventuali modifiche e distribuisci gli adattamenti
con `CC BY-SA 4.0` o con una licenza compatibile ShareAlike.

Riferimenti:

- [Avviso di licenza del progetto](LICENSE.md)
- [Creative Commons BY-SA 4.0, URL canonico](https://creativecommons.org/licenses/by-sa/4.0/)
- [Creative Commons BY-SA 4.0, testo legale][cc-legal]
- [SPDX: CC-BY-SA-4.0](https://spdx.org/licenses/CC-BY-SA-4.0.html)

[cc-legal]: https://creativecommons.org/licenses/by-sa/4.0/legalcode
