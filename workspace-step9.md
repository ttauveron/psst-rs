# Workspace — Étape 9

## Objectif

Renforcer la couverture de tests et les garanties de sécurité restantes, avec un focus sur le frontend navigateur et l’absence de données sensibles dans les logs.

## Découpage des tâches

### 9.1 — Cartographier ce qui est déjà couvert

* Lister les critères d’acceptation encore non prouvés de `SPECS.md`.
* Distinguer backend déjà couvert et frontend encore peu couvert.
* Confirmer que la priorité est le JavaScript navigateur et la journalisation.

**Terminé quand**

* Les trous de couverture sont identifiés précisément.

### 9.2 — Rendre `static/app.js` testable

* Extraire les helpers purs critiques :
  chiffrement, déchiffrement, calcul de taille UTF-8, lecture/effacement du fragment.
* Réduire le couplage direct avec le DOM dans les chemins critiques.
* Exposer des hooks de test uniquement si un conteneur de tests est préinstallé.

**Terminé quand**

* Les comportements critiques peuvent être testés sans navigateur réel.

### 9.3 — Ajouter un harness de tests frontend sans dépendances externes

* Utiliser `node --test`.
* Créer un mini faux DOM suffisant pour `app.js`.
* Charger le script dans un contexte contrôlé.

**Terminé quand**

* Les tests frontend s’exécutent localement sans installer de bibliothèque JS supplémentaire.

### 9.4 — Écrire les tests frontend ciblés

* Tester un round-trip chiffrement/déchiffrement.
* Tester la clé absente sur la page de lecture.
* Tester la clé invalide ou malformée.
* Tester le compteur de taille UTF-8.
* Tester le nettoyage du fragment après lecture réussie.

**Terminé quand**

* Les scénarios frontend demandés par `ROADMAP.md` sont couverts.

### 9.5 — Ajouter les tests de non-fuite dans les logs

* Capturer la sortie `tracing` en test.
* Vérifier qu’un secret ID réel de route paramétrée n’apparaît pas dans les logs.
* Vérifier qu’un body JSON sensible n’apparaît pas dans les logs.
* Vérifier qu’aucun fragment ou token n’est journalisé.

**Terminé quand**

* Les tests prouvent que la journalisation reste minimale et non sensible.

### 9.6 — Intégrer l’exécution des tests

* Ajouter une commande frontend de test au flux de dev.
* Mettre à jour `Makefile` et la doc si nécessaire.

**Terminé quand**

* `make test` couvre la suite Rust et la suite frontend.

## Ordre recommandé

1. Refactor minimal de `static/app.js`.
2. Harness Node natif.
3. Tests frontend ciblés.
4. Tests de logs sensibles.
5. Intégration dans `Makefile` et la doc.
