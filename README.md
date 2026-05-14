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

## Etat actuel

Ce depot couvre aujourd'hui :

- le backend de creation, lecture unique et suppression ;
- le chiffrement/dechiffrement dans le navigateur ;
- l'interface v1 ;
- les tests backend et HTTP.

Les protections anti-abus avancees prevues plus tard, comme la vraie verification Turnstile et le rate limiting, ne sont pas encore branchees.
