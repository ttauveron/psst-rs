# Spécifications — Service minimaliste de partage de secrets

## 1. Résumé

Construire un service web minimaliste permettant de partager un secret chiffré via un lien à usage unique. Le service ne doit pas être un gestionnaire de mots de passe, ni un pastebin, ni un service de fichiers. Il doit être un transporteur éphémère de petits secrets.

Le service doit être public en lecture, sans compte utilisateur, sans adresse email, sans login, sans panneau d’administration complexe. La création d’un secret est protégée par Cloudflare Turnstile et par des limites côté application. Le secret est chiffré côté navigateur ; le serveur ne reçoit jamais la clé de déchiffrement.

Nom produit : `psst`.

Nom technique du projet : `psst-rs`.

## 2. Objectifs

* Permettre à quelqu’un de créer un petit secret et d’obtenir un lien partageable.
* Permettre au destinataire d’ouvrir le lien une seule fois.
* Supprimer automatiquement le secret après lecture ou expiration.
* Ne jamais stocker ni voir le secret en clair côté serveur.
* Rester extrêmement léger : un binaire Rust, SQLite, HTML/CSS/JS statique.
* Pouvoir tourner confortablement sur une VM 1 vCPU / 1 Go RAM / 10 Go disque.
* Être raisonnablement exposable publiquement derrière Cloudflare.

## 3. Non-objectifs

Le projet ne doit pas inclure :

* comptes utilisateurs ;
* login par email ;
* mots de passe utilisateurs ;
* gestion de rôles ;
* pièces jointes ;
* upload de fichiers ;
* secrets permanents ;
* lecture multiple ;
* historique des secrets ;
* recherche ;
* liste publique ou privée des secrets ;
* notification email ;
* API publique non protégée ;
* rendu HTML du contenu secret ;
* dépendance à un framework frontend.

## 4. Contraintes principales

### 4.1 Taille maximale

La taille maximale d’un secret en clair avant chiffrement est de 16 KiB.

Le serveur doit aussi imposer une limite stricte sur la taille du payload chiffré reçu, par exemple 32 KiB, pour tenir compte de l’overhead JSON/base64/chiffrement.

### 4.2 Expiration

Options proposées dans l’interface :

* 15 minutes ;
* 1 heure ;
* 24 heures ;
* 7 jours ;

Valeur par défaut : 24 heures.

### 4.3 Lecture unique

Tous les secrets sont à lecture unique. Il ne doit pas exister d’option permettant plusieurs lectures.

Lorsqu’un secret est récupéré avec succès par l’API, il est immédiatement marqué comme consommé ou supprimé dans une transaction SQLite.

### 4.4 Chiffrement côté client

Le navigateur génère une clé aléatoire, chiffre le secret localement, envoie uniquement le ciphertext au serveur, puis place la clé dans le fragment d’URL après `#`.

Exemple :

```text
https://example.tld/s/abc123#base64url-key
```

Le fragment ne doit jamais être envoyé volontairement au serveur par le JavaScript.

### 4.5 Pas de logs sensibles

L’application ne doit jamais logger :

* le secret en clair ;
* le ciphertext complet ;
* la clé ;
* le fragment d’URL ;
* le body complet des requêtes ;
* les tokens Turnstile ;
* les cookies ;
* les headers sensibles.

## 5. Architecture cible

```text
Client browser
  ↓ HTTPS
Cloudflare
  ↓ HTTPS
nginx sur Alpine
  ↓ HTTP local
psst-rs sur 127.0.0.1:3000
  ↓
SQLite /var/lib/psst-rs/secrets.db
```

L’application Rust n’a pas besoin de gérer TLS directement. TLS est terminé par nginx. L’application écoute uniquement sur `127.0.0.1`.

## 6. Technologies recommandées

### 6.1 Backend

Langage : Rust.

Choix recommandé pour la première version :

* `axum` pour le serveur HTTP ;
* `tokio` comme runtime ;
* `rusqlite` ou `sqlx` avec SQLite ;
* `serde` / `serde_json` pour JSON ;
* `askama`, `maud`, ou templates statiques simples pour HTML ;
* `rand` pour les identifiants ;
* `base64` pour l’encodage base64url ;
* `reqwest` uniquement si nécessaire pour vérifier Turnstile côté serveur.

Alternative plus minimaliste : serveur synchrone avec `tiny-http` ou équivalent. Mais `axum` est probablement le meilleur compromis maintenabilité/sécurité.

### 6.2 Frontend

* HTML statique ;
* CSS local, fichier unique ;
* JavaScript local, fichier unique ;
* Web Crypto API pour le chiffrement/déchiffrement ;
* aucun framework ;
* aucun script externe sauf le script Cloudflare Turnstile si Turnstile est utilisé côté client.

### 6.3 Base de données

SQLite local.

Un seul fichier de base suffit. Le service doit pouvoir recréer automatiquement le schéma au démarrage si la base est vide.

## 7. Modèle de menace simplifié

### 7.1 Attaquant opportuniste

L’attaquant essaie de créer beaucoup de secrets, de remplir le disque, de contourner Turnstile, ou d’utiliser le service comme pastebin chiffré.

Mitigations : Turnstile, taille max 16 KiB, rate limit, quota global, expiration, lecture unique.

### 7.2 Destinataire curieux

Le destinataire peut copier le secret après affichage. C’est hors périmètre. Une fois affiché, le service ne peut plus contrôler ce que l’utilisateur fait du secret.

### 7.3 Personne ayant accès au serveur

Elle peut voir les ciphertexts, les métadonnées et la base SQLite, mais pas les secrets en clair si la clé n’a jamais été transmise au serveur.

### 7.4 Compromission du JavaScript servi

Si un attaquant modifie le JavaScript servi par le site, il peut voler les secrets lors de la création ou de la lecture. Mitigations : pas de scripts tiers, CSP stricte, déploiement simple, permissions système limitées, checksums optionnels.

## 8. Routes HTTP

### 8.1 Pages HTML

#### `GET /`

Affiche le formulaire de création.

Contient :

* textarea pour le secret ;
* choix d’expiration ;
* widget Turnstile ;
* bouton de création ;
* rappel de la limite 16 KiB ;
* mention : “Le secret est chiffré dans votre navigateur. Le serveur ne reçoit pas la clé.”

#### `GET /s/:id`

Affiche la page de lecture.

Cette page contient le JavaScript de déchiffrement. Elle lit la clé depuis `window.location.hash`, appelle l’API pour récupérer le ciphertext, déchiffre localement, affiche le secret en texte brut, puis efface idéalement le fragment de l’URL via `history.replaceState`.

Si le fragment est absent, afficher une erreur claire : “Lien incomplet : clé manquante.”

#### `GET /about`

Page courte expliquant :

* chiffrement côté client ;
* lecture unique ;
* expiration ;
* absence de récupération possible ;
* limites.

### 8.2 API

#### `POST /api/create`

Crée un secret.

Requête JSON :

```json
{
  "ciphertext": "base64url...",
  "nonce": "base64url...",
  "expires_in_seconds": 86400,
  "turnstile_token": "..."
}
```

Réponse JSON :

```json
{
  "id": "abc123...",
  "delete_token": "def456..."
}
```

Le client construit ensuite le lien complet :

```text
/s/{id}#{key}
```

Validation serveur :

* méthode POST uniquement ;
* `Content-Type: application/json` ;
* taille de body maximale ;
* Turnstile valide ;
* expiration autorisée ;
* ciphertext dans la limite ;
* nonce présent ;
* rate limit IP OK ;
* quota global OK.

Le serveur ne reçoit pas la clé de chiffrement.

#### `GET /api/secrets/:id`

Récupère un secret chiffré et le consomme.

Réponse succès :

```json
{
  "ciphertext": "base64url...",
  "nonce": "base64url..."
}
```

Cette opération doit être atomique : si deux requêtes arrivent en même temps, une seule doit obtenir le secret.

Réponses possibles :

* 200 : secret retourné et consommé ;
* 404 : secret inexistant, expiré ou déjà lu ;
* 410 : optionnel, secret expiré ou consommé ;
* 429 : rate limit.

Pour limiter l’énumération, il est acceptable de répondre 404 pour “inexistant”, “expiré” et “déjà lu”.

#### `POST /api/delete/:id`

Supprime un secret avant lecture via un delete token.

Requête JSON :

```json
{
  "delete_token": "..."
}
```

Le token de suppression doit être stocké haché côté serveur.

Réponse :

```json
{
  "deleted": true
}
```

#### `GET /healthz`

Retourne `200 OK` si le service est vivant.

Ne doit exposer aucune information sensible.

## 9. Schéma SQLite

```sql
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  delete_token_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  requester_ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_secrets_expires_at
ON secrets(expires_at);

CREATE INDEX IF NOT EXISTS idx_secrets_consumed_at
ON secrets(consumed_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (key, bucket)
);
```

Le champ `requester_ip_hash` est optionnel. S’il est utilisé, il doit être dérivé avec un sel serveur non public et ne doit pas conserver l’IP brute.

## 10. Identifiants et tokens

### 10.1 Secret ID

* Aléatoire cryptographiquement sûr.
* Minimum 128 bits d’entropie.
* Encodage base64url sans padding ou base62.
* Non séquentiel.

### 10.2 Delete token

* Aléatoire cryptographiquement sûr.
* Minimum 128 bits d’entropie.
* Retourné uniquement à la création.
* Stocké haché côté serveur.

### 10.3 Clé de chiffrement

* Générée côté navigateur via Web Crypto API.
* Non transmise au serveur.
* Encodée dans le fragment d’URL.

## 11. Chiffrement côté navigateur

Algorithme recommandé : AES-GCM 256 bits.

Processus de création :

1. Lire le secret dans le textarea.
2. Vérifier que sa taille UTF-8 est <= 16 KiB.
3. Générer une clé AES-GCM 256 bits.
4. Générer un nonce/IV unique de 96 bits.
5. Chiffrer le secret localement.
6. Envoyer ciphertext + nonce + expiration + token Turnstile au serveur.
7. Recevoir l’ID.
8. Construire le lien `/s/{id}#{key}`.

Processus de lecture :

1. Lire `id` depuis l’URL.
2. Lire `key` depuis `window.location.hash`.
3. Si la clé manque, afficher une erreur.
4. Appeler `GET /api/secrets/:id`.
5. Recevoir ciphertext + nonce.
6. Déchiffrer localement.
7. Afficher le secret en texte brut.
8. Effacer le fragment de l’URL avec `history.replaceState`.

## 12. Rate limiting

### 12.1 Côté Cloudflare

Protéger au minimum :

* `POST /api/create` ;
* éventuellement `GET /api/secrets/:id` en cas d’abus.

Actions recommandées : managed challenge, block temporaire ou throttle selon les capacités disponibles.

### 12.2 Côté application

Implémenter un rate limit minimal même si Cloudflare est actif.

Règles initiales proposées :

* création : 5 par minute par IP hashée ;
* création : 30 par heure par IP hashée ;
* lecture : limite souple, par exemple 60 par minute par IP hashée ;
* stockage global : 50 MiB maximum ;
* secrets actifs globaux : 10 000 maximum.

Ces valeurs doivent être configurables par variables d’environnement.

## 13. Purge

Un job périodique interne doit supprimer :

* secrets expirés ;
* secrets consommés depuis plus de quelques minutes ;
* vieux enregistrements de rate limit.

Fréquence recommandée : toutes les 5 minutes.

Un redémarrage du service ne doit pas invalider les secrets encore valides. L’expiration doit être appliquée au moment de la lecture, puis la suppression physique peut être faite par le job périodique.

## 14. Configuration

Variables d’environnement :

```text
SECRET_RS_BIND_ADDR=127.0.0.1:3000
SECRET_RS_DATABASE_PATH=/var/lib/psst-rs/secrets.db
SECRET_RS_PUBLIC_BASE_URL=https://example.tld
SECRET_RS_MAX_SECRET_BYTES=16384
SECRET_RS_MAX_CIPHERTEXT_BYTES=32768
SECRET_RS_DEFAULT_TTL_SECONDS=86400
SECRET_RS_MAX_TTL_SECONDS=2592000
SECRET_RS_TURNSTILE_SITE_KEY=...
SECRET_RS_TURNSTILE_SECRET_KEY=...
SECRET_RS_IP_HASH_SALT=...
SECRET_RS_GLOBAL_MAX_ACTIVE_SECRETS=10000
SECRET_RS_GLOBAL_MAX_STORAGE_BYTES=52428800
SECRET_RS_MAINTENANCE_INTERVAL_SECONDS=300
SECRET_RS_ENABLE_CREATE=true
```

Si `SECRET_RS_ENABLE_CREATE=false`, la page de création doit afficher que la création est temporairement désactivée et `POST /api/create` doit retourner 503.

## 15. Headers de sécurité

Réponses HTML :

```text
Content-Security-Policy: default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

Cookies : si utilisés, ils doivent être `HttpOnly`, `Secure`, `SameSite=Strict` ou `SameSite=Lax`. La v1 ne devrait pas nécessiter de cookies applicatifs.

## 16. Journalisation

Loguer uniquement des événements techniques non sensibles.

Exemples acceptables :

```text
time=... event=create_secret status=ok size=312 ttl=86400
```

Exemples interdits :

```text
time=... body={...}
time=... ciphertext=...
time=... url=https://example.tld/s/id#key
```

Les logs doivent être courts et compatibles avec une rotation agressive.

## 17. Interface utilisateur

### 17.1 Page de création

Texte recommandé :

```text
Collez un petit secret. Il sera chiffré dans votre navigateur avant d’être envoyé au serveur.
Limite : 16 KiB. Lecture unique. Suppression automatique après expiration.
```

Champs :

* textarea ;
* compteur de taille ;
* select expiration ;
* Turnstile ;
* bouton “Créer le lien”.

Après création :

* afficher le lien complet ;
* bouton “Copier” ;
* bouton “Supprimer maintenant” utilisant le delete token ;
* avertissement : “Si vous perdez ce lien, le secret ne peut pas être récupéré.”

### 17.2 Page de lecture

Avant lecture :

```text
Ce secret ne pourra être affiché qu’une seule fois.
```

Bouton :

```text
Afficher le secret
```

Après lecture :

* afficher le secret dans un bloc texte ;
* bouton copier ;
* indiquer qu’il a été supprimé côté serveur.

Si erreur :

```text
Ce secret est introuvable, expiré ou déjà lu.
```

Ne pas révéler précisément lequel de ces cas s’applique.

## 18. Cloudflare recommandé

### 18.1 DNS

* Domaine dédié.
* Proxy Cloudflare activé.
* Aucun record exposant inutilement l’IP d’origine.

### 18.2 WAF / challenges

Règles recommandées :

* challenge ou protection renforcée sur `POST /api/create` ;
* rate limit sur `POST /api/create` ;
* blocage des méthodes HTTP non utilisées ;
* challenge sur trafic suspect.

### 18.3 Origine

Le firewall de la VM doit accepter 80/443 uniquement depuis les IP Cloudflare. SSH doit être limité à une IP connue ou à un VPN.

## 19. Déploiement Alpine

### 19.1 Fichiers

```text
/usr/local/bin/psst-rs
/etc/psst-rs/env
/etc/init.d/psst-rs
/var/lib/psst-rs/secrets.db
/var/log/psst-rs/
```

### 19.2 OpenRC

Créer un service OpenRC lançant le binaire avec l’environnement chargé depuis `/etc/psst-rs/env`.

L’utilisateur système `psst-rs` doit être non-root et propriétaire de `/var/lib/psst-rs`.

## 20. Compilation Rust pour petit binaire

Profil release recommandé :

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

Si la performance est préférée à la taille, utiliser `opt-level = "s"` ou `opt-level = 3` après mesure.

## 21. Critères d’acceptation

La v1 est acceptable si :

* un secret de moins de 16 KiB peut être créé ;
* le serveur ne reçoit jamais la clé de déchiffrement ;
* le lien contient la clé uniquement après `#` ;
* un secret peut être lu une seule fois ;
* une deuxième lecture retourne 404 ou 410 ;
* un secret expiré est inaccessible ;
* la purge supprime les secrets expirés ;
* Turnstile est vérifié côté serveur ;
* `POST /api/create` refuse les payloads trop gros ;
* `POST /api/create` refuse les expirations trop longues ;
* les logs ne contiennent ni secret, ni ciphertext complet, ni clé ;
* le service peut démarrer avec une base vide ;
* le service tourne derrière Caddy/nginx sur localhost ;
* le binaire fonctionne sur Alpine Linux ;
* le service reste sous 100 Mo de RAM au repos dans une configuration normale.

## 22. Tests à prévoir

### 22.1 Tests backend

* création OK ;
* création refusée si trop gros ;
* création refusée si TTL invalide ;
* lecture unique atomique ;
* expiration ;
* suppression par delete token ;
* delete token invalide ;
* rate limit ;
* quota global ;
* purge ;
* absence de secret dans les logs.

### 22.2 Tests frontend

* chiffrement/déchiffrement AES-GCM ;
* clé absente ;
* clé invalide ;
* secret trop gros ;
* compteur de taille ;
* copie du lien ;
* copie du secret ;
* nettoyage du fragment après lecture.

### 22.3 Tests de sécurité simples

* deux lectures simultanées du même secret : une seule réussit ;
* IDs impossibles à deviner en pratique ;
* pas de rendu HTML du secret ;
* CSP présente ;
* headers de sécurité présents ;
* body trop gros rejeté avant traitement lourd ;
* méthodes non supportées rejetées.

## 23. Décisions ouvertes

* Utiliser `axum` ou un serveur HTTP plus minimaliste.
* Utiliser `rusqlite` ou `sqlx`.
* Supprimer physiquement le secret dès lecture ou marquer `consumed_at` puis purger quelques minutes plus tard.
* Autoriser l’expiration 30 jours par défaut dans l’UI ou la placer derrière une option avancée.
* Stocker ou non des IP hashées pour le rate limiting persistant.

## 24. Recommandation v1

Pour la première version, choisir :

* Rust + axum ;
* SQLite + rusqlite ;
* Web Crypto AES-GCM côté client ;
* Cloudflare Turnstile sur création ;
* 16 KiB max ;
* expiration par défaut 24 h ;
* expiration max 30 jours ;
* lecture unique obligatoire ;
* suppression immédiate après lecture ;
* logs minimaux ;
* domaine dédié ;
* Cloudflare devant ;
* origine verrouillée.
