# ROADMAP — `secret-rs`

## Objectif

Construire un service web minimaliste de partage de secrets à lecture unique, chiffrés côté navigateur, avec un backend Rust léger, SQLite, et un frontend statique sans framework.

Cette roadmap découpe le projet en étapes courtes et vérifiables, afin de pouvoir avancer pas à pas sans perdre les contraintes de sécurité définies dans `SPECS.md`.

## Principes de mise en oeuvre

* Toujours livrer un incrément testable.
* Verrouiller tôt les contraintes sensibles : chiffrement côté client, lecture unique atomique, absence de logs sensibles.
* Garder la v1 minimale : pas de comptes, pas de fichiers, pas d’API publique large.
* Préférer la simplicité opérationnelle : un binaire Rust, SQLite, assets statiques, déploiement derrière nginx/Cloudflare.

## Choix retenus pour la v1

* Backend : Rust + `axum` + `tokio`
* Base de données : SQLite + `rusqlite`
* Frontend : HTML/CSS/JS statiques
* Chiffrement navigateur : Web Crypto API, AES-GCM 256
* Lecture unique : suppression immédiate dans une transaction SQLite
* Anti-abus : Cloudflare Turnstile + rate limiting applicatif
* Stockage des IP : IP hashées avec un sel serveur, jamais stockées en clair

## Ordre de réalisation

### Étape 1 — Initialiser le squelette du projet

**But**

Créer une base de travail propre pour le backend, le frontend statique et la configuration.

**Travail**

* Initialiser le projet Cargo.
* Ajouter les dépendances minimales (`axum`, `tokio`, `rusqlite`, `serde`, `tracing`, etc.).
* Définir l’arborescence du projet : `src/`, `static/`, éventuels templates, configuration.
* Mettre en place le chargement des variables d’environnement.
* Exposer un serveur HTTP local sur `127.0.0.1:3000`.
* Ajouter `GET /healthz`.

**Terminé quand**

* Le binaire démarre localement.
* `GET /healthz` retourne `200 OK`.
* La configuration minimale est centralisée et validée au démarrage.

### Étape 2 — Poser les fondations sécurité HTTP

**But**

Éviter dès le départ les erreurs de base sur les headers, les méthodes et les logs.

**Travail**

* Ajouter les headers de sécurité sur les réponses HTML.
* Rejeter les méthodes non supportées.
* Limiter la taille des requêtes JSON.
* Poser une stratégie de journalisation minimale, sans données sensibles.
* Prévoir le middleware de récupération d’IP client via headers proxy de confiance.

**Terminé quand**

* Les pages HTML renvoient CSP, `Referrer-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Permissions-Policy`.
* Les logs ne contiennent ni body de requête ni secrets ni fragments d’URL.
* Les routes API sensibles ont déjà des garde-fous de taille/méthode.

### Étape 3 — Mettre en place SQLite et le schéma

**But**

Disposer d’une couche de persistence simple et robuste.

**Travail**

* Créer le schéma SQLite au démarrage.
* Implémenter les tables `secrets`, `abuse_reports`, `rate_limits`.
* Ajouter les index nécessaires.
* Encapsuler l’accès DB dans une couche dédiée.
* Prévoir les primitives atomiques nécessaires à la lecture unique.

**Terminé quand**

* Une base vide est initialisée automatiquement.
* Les opérations DB principales sont isolées dans une API interne claire.
* La transaction “lire et consommer” est techniquement possible.

### Étape 4 — Implémenter le coeur métier des secrets

**But**

Faire fonctionner le cycle de vie minimal d’un secret côté serveur.

**Travail**

* Générer des IDs aléatoires robustes.
* Générer un `delete_token` et stocker uniquement son hash.
* Implémenter `POST /api/create`.
* Implémenter `GET /api/secrets/:id` avec consommation atomique.
* Implémenter `POST /api/delete/:id`.
* Valider TTL, tailles max et quotas simples.

**Terminé quand**

* Un secret chiffré peut être créé, lu une seule fois, puis devient introuvable.
* Un `delete_token` valide permet une suppression anticipée.
* Les tailles et TTL hors limites sont refusés proprement.

### Étape 5 — Construire le chiffrement côté navigateur

**But**

Garantir que la clé n’est jamais transmise au serveur.

**Travail**

* Créer la page `GET /`.
* Implémenter en JavaScript le chiffrement AES-GCM.
* Générer la clé côté navigateur.
* Encoder la clé dans le fragment d’URL `#...`.
* Créer la page `GET /s/:id`.
* Implémenter le déchiffrement côté lecture.
* Effacer le fragment avec `history.replaceState` après lecture.

**Terminé quand**

* Le serveur reçoit uniquement `ciphertext` et `nonce`.
* Le lien généré contient la clé uniquement après `#`.
* Un destinataire peut ouvrir le lien et déchiffrer localement le secret.

### Étape 6 — Finaliser l’interface utilisateur v1

**But**

Rendre le flux de création/lecture utilisable sans sacrifier la simplicité.

**Travail**

* Ajouter le textarea, compteur de taille, sélection d’expiration, bouton de création.
* Afficher le lien complet après création.
* Ajouter le bouton “Copier”.
* Ajouter le bouton “Supprimer maintenant”.
* Ajouter les pages `GET /about` et `GET /abuse`.
* Ajouter les messages d’erreur attendus : clé absente, secret introuvable, création désactivée, etc.

**Terminé quand**

* Le parcours utilisateur principal fonctionne sans outil externe.
* Les textes rappellent clairement les contraintes : 16 KiB, lecture unique, récupération impossible.
* Les erreurs sont compréhensibles sans révéler d’informations sensibles.

### Étape 7 — Ajouter Turnstile, rate limiting et anti-abus

**But**

Bloquer les abus évidents avant ouverture publique.

**Travail**

* Intégrer Cloudflare Turnstile dans le formulaire de création.
* Vérifier le token Turnstile côté serveur.
* Implémenter une limite de création par minute par IP hashée.
* Implémenter une limite de création par heure par IP hashée.
* Implémenter une limite de lecture souple par IP hashée.
* Implémenter une limite de signalement par IP hashée.
* Implémenter des quotas globaux en nombre de secrets actifs et en volume total.
* Implémenter `POST /api/report`.
* Ajouter un mode `SECRET_RS_ENABLE_CREATE=false`.

**Terminé quand**

* La création sans Turnstile valide est refusée.
* Les abus simples déclenchent des `429` ou `503` adaptés.
* L’application peut temporairement désactiver la création.

### Étape 8 — Implémenter la purge et l’entretien

**But**

Éviter l’accumulation de données et faire respecter l’expiration dans la durée.

**Travail**

* Ajouter une purge au démarrage.
* Ajouter un job périodique interne.
* Supprimer secrets expirés, secrets consommés, vieux buckets de rate limit, vieux reports selon politique.
* Mesurer les compteurs globaux à partir de la base.

**Terminé quand**

* Les secrets expirés deviennent inaccessibles puis sont purgés.
* Les données temporaires ne grossissent pas indéfiniment.
* Le service reste stable dans le temps sans intervention manuelle.

### Étape 9 — Renforcer les tests et les garanties de sécurité

**But**

Valider les cas limites et les propriétés de sécurité les plus importantes.

**Travail**

* Écrire les tests backend : création, refus, lecture unique, suppression, expiration, quota, purge.
* Écrire les tests frontend ciblés : chiffrement/déchiffrement, clé absente, clé invalide, compteur, nettoyage du fragment.
* Vérifier qu’une double lecture concurrente ne réussit qu’une seule fois.
* Vérifier la présence des headers de sécurité.
* Vérifier l’absence de données sensibles dans les logs de test.

**Terminé quand**

* Les critères d’acceptation de `SPECS.md` sont couverts.
* Le comportement concurrent critique est prouvé par test.
* Le niveau de confiance est suffisant pour exposition publique contrôlée.

### Étape 10 — Préparer le déploiement Alpine

**But**

Rendre la v1 exploitable sur une petite VM derrière nginx et Cloudflare.

**Travail**

* Optimiser le profil de build release.
* Préparer les chemins de déploiement et le fichier d’environnement.
* Rédiger le service OpenRC.
* Documenter les permissions système et l’utilisateur dédié `secret-rs`.
* Documenter la configuration nginx locale et les points Cloudflare nécessaires.

**Terminé quand**

* Le binaire release est prêt pour Alpine.
* Le service peut démarrer automatiquement via OpenRC.
* Le chemin de déploiement est documenté de bout en bout.

## Découpage pratique des livraisons

Pour avancer sans blocage, on peut suivre ce rythme :

1. Étapes 1 à 3 : fondations techniques.
2. Étapes 4 à 6 : produit fonctionnel local de bout en bout.
3. Étapes 7 et 8 : anti-abus et exploitation durable.
4. Étapes 9 et 10 : qualité, hardening et mise en production.

## Premier jalon recommandé

Commencer par livrer un backend minimal avec :

* serveur `axum` ;
* config ;
* `GET /healthz` ;
* initialisation SQLite ;
* structure de projet propre.

Ce premier jalon réduit fortement l’incertitude et prépare toutes les étapes suivantes.
