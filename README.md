# psst-rs

`psst` est un service minimal de partage de secrets a lecture unique. Le nom technique du projet reste `psst-rs`.

Le secret est chiffre dans le navigateur avec AES-GCM. Le serveur ne recoit que le `ciphertext` et le `nonce`. La cle reste uniquement dans le fragment d'URL, apres `#`.

## Prerequis

- Rust et Cargo
- un navigateur recent avec Web Crypto API

## Lancer les tests automatises

Compilation rapide :

```bash
cargo check
```

Suite de tests :

```bash
cargo test
```

## Deploiement home lab

Le flux le plus simple passe par le `Makefile` du repo.

1. Cree `.env` a la racine depuis `.env.example`.
2. Renseigne :

```dotenv
CLOUDFLARE_API_TOKEN=...
PSST_TURNSTILE_SITE_KEY=...
PSST_TURNSTILE_SECRET_KEY=...
```

3. Lance :

```bash
make deploy
```

Cette commande :

- compile un binaire release compatible Alpine via musl ;
- le copie vers `ansible/files/bin/psst-rs` ;
- applique Terraform ;
- deploie avec Ansible.

Le fichier `.env` est ignore par Git. Ne committe pas de secrets ; garde seulement `.env.example` dans le repo.

Pour le dev local, `make build-release` conserve un build natif de ta machine. Le packaging de deploiement passe par `make build-release-alpine` dans un conteneur Docker.

Si Terraform est deja applique et que tu veux seulement redéployer l'application :

```bash
make deploy-no-terraform
```

Les tests couvrent actuellement :

- la configuration ;
- la couche SQLite ;
- le cycle de vie des secrets ;
- les routes HTTP ;
- les shells HTML utilises par l'interface navigateur.

## Lancer le service en local

Par defaut, l'application essaie d'utiliser `/var/lib/psst-rs/secrets.db`, ce qui n'est pas pratique en dev. Pour un test local, utilise un chemin dans `/tmp`.

```bash
SECRET_RS_DATABASE_PATH=/tmp/psst-rs-dev.db cargo run
```

Le serveur ecoute ensuite sur :

```text
http://127.0.0.1:3000
```

Verification rapide :

```bash
curl -i http://127.0.0.1:3000/healthz
```

La reponse attendue est :

```text
HTTP/1.1 200 OK
...

ok
```

## Tester le flux principal dans le navigateur

1. Lance le serveur localement :

   ```bash
   SECRET_RS_DATABASE_PATH=/tmp/psst-rs-dev.db cargo run
   ```

2. Ouvre `http://127.0.0.1:3000/`.

3. Saisis un secret dans le textarea.

4. Choisis une expiration.

5. Clique sur `Create psst link`.

6. Verifie qu'un lien apparait sous la forme :

   ```text
   https://example.tld/s/<id>#<cle>
   ```

   En local, l'hote du lien depend de `SECRET_RS_PUBLIC_BASE_URL`. Par defaut il vaut `https://example.tld`. Pour un test local plus naturel tu peux lancer :

   ```bash
   SECRET_RS_DATABASE_PATH=/tmp/psst-rs-dev.db \
   SECRET_RS_PUBLIC_BASE_URL=http://127.0.0.1:3000 \
   cargo run
   ```

### Turnstile en local

Si ton widget Turnstile echoue sur `http://127.0.0.1:3000` ou `http://localhost:3000`, la cause la plus probable est que ta cle Cloudflare de production n'autorise pas les domaines locaux.

Deux options simples :

1. utiliser les cles de test Cloudflare en local :

   ```bash
   SECRET_RS_DATABASE_PATH=/tmp/psst-rs-dev.db \
   SECRET_RS_PUBLIC_BASE_URL=http://127.0.0.1:3000 \
   SECRET_RS_TURNSTILE_SITE_KEY=1x00000000000000000000AA \
   SECRET_RS_TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA \
   cargo run
   ```

2. ou autoriser `localhost` et `127.0.0.1` dans la configuration Hostname Management de ton widget Turnstile.

Les cles de test Cloudflare fonctionnent sur les domaines locaux et renvoient toujours une validation reussie pour ce couple de test. Source : Cloudflare Turnstile testing docs (`https://developers.cloudflare.com/turnstile/troubleshooting/testing/`).

7. Ouvre le lien complet dans un autre onglet ou une autre fenetre.

8. Verifie que le secret s'affiche correctement.

9. Recharge la page de lecture. Le secret doit maintenant etre introuvable, car il a ete consomme.

## Tester la suppression anticipee

1. Cree un secret depuis la page d'accueil.
2. Clique sur `Supprimer maintenant`.
3. Ouvre ensuite le lien genere.
4. Le secret doit etre indisponible.

Important : le `delete_token` est conserve uniquement en memoire dans le navigateur courant. Si tu fermes la page avant de cliquer sur `Supprimer maintenant`, tu perds cette possibilite pour cette session de test.

## Tester quelques cas limites utiles

### Creation desactivee

Lance le serveur avec :

```bash
SECRET_RS_DATABASE_PATH=/tmp/psst-rs-dev.db \
SECRET_RS_ENABLE_CREATE=false \
cargo run
```

Effet attendu :

- le formulaire est desactive ;
- l'interface affiche que la creation est temporairement desactivee.

### Cle manquante

1. Cree un secret.
2. Ouvre `/s/<id>` sans la partie `#<cle>`.

Effet attendu :

- la page affiche `Lien incomplet : cle manquante.`

### Secret deja lu ou supprime

1. Lis un secret une premiere fois, ou supprime-le avec `Supprimer maintenant`.
2. Reviens sur le meme lien.

Effet attendu :

- la page affiche que le secret est introuvable, expire ou deja lu.

## Variables d'environnement utiles en dev

- `SECRET_RS_DATABASE_PATH` : chemin du fichier SQLite
- `SECRET_RS_PUBLIC_BASE_URL` : base utilisee pour construire le lien final
- `SECRET_RS_BIND_ADDR` : adresse d'ecoute, par defaut `127.0.0.1:3000`
- `SECRET_RS_ENABLE_CREATE` : active ou desactive la creation
- `SECRET_RS_MAX_SECRET_BYTES` : limite plaintext avant chiffrement, par defaut `16384`
- `SECRET_RS_TURNSTILE_SITE_KEY` : cle publique Turnstile
- `SECRET_RS_TURNSTILE_SECRET_KEY` : cle privee Turnstile
- `SECRET_RS_IP_HASH_SALT` : sel serveur utilise pour pseudonymiser les IP
- `SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE` : limite de creation par minute et par IP hashée, par defaut `5`
- `SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR` : limite de creation par heure et par IP hashée, par defaut `30`
- `SECRET_RS_READ_RATE_LIMIT_PER_MINUTE` : limite souple de lecture par minute et par IP hashée, par defaut `60`

## Rate limiting

Le service applique maintenant :

- une limite de creation par minute et par heure, basee sur une IP pseudonymisee ;
- une limite souple de lecture par minute, egalement basee sur une IP pseudonymisee ;
- des quotas globaux distincts sur le nombre de secrets actifs et le volume stocke.

Les limites IP renvoient `429 Too Many Requests`. Les indisponibilites globales, comme la creation desactivee ou un quota global depasse, renvoient `503 Service Unavailable`.

Le detail du comportement est documente dans [docs/rate-limiting.md](docs/rate-limiting.md).

## Etat actuel

Ce depot couvre aujourd'hui :

- le backend de creation, lecture unique et suppression ;
- le chiffrement/dechiffrement dans le navigateur ;
- l'interface v1 ;
- les tests backend et HTTP ;
- la verification Turnstile cote serveur ;
- le rate limiting de creation et de lecture.
