# Ansible

Structure minimale pour deployer `psst-rs` sur une VM Alpine avec OpenRC et nginx.

## Artefacts locaux a fournir

- `files/bin/psst-rs` : binaire Rust deja compile pour la VM cible
- `files/tls/origin.crt` : certificat TLS
- `files/tls/origin.key` : cle privee TLS

Ces fichiers sont ignores par Git. Pour la cle TLS, prefere un fichier hors repo ou Ansible Vault.

## Jonction Terraform

Par defaut, le playbook essaie de lire les outputs Terraform dans `../terraform` pour recuperer automatiquement:

- `cloudflare_hostname`
- `cloudflare_origin_ca_certificate_pem`
- `cloudflare_origin_ca_private_key_pem`

Quand ces outputs sont disponibles, Ansible:

- derive `psst_domain` et `psst_public_base_url` depuis Terraform ;
- installe le certificat Origin CA et sa cle privee sans passer par `files/tls/*`.

Si Terraform n'est pas pret ou si tu veux rester en mode manuel, mets:

```yaml
psst_use_terraform_outputs: false
```

Dans ce cas, Ansible revient au comportement initial et attend `files/tls/origin.crt` et `files/tls/origin.key`.

## Execution

Le flux le plus simple pour un home lab passe par le `Makefile` a la racine du repo.

1. Cree un fichier `.env` a la racine a partir de `.env.example`.
2. Renseigne dedans :

```dotenv
CLOUDFLARE_API_TOKEN=...
PSST_TURNSTILE_SITE_KEY=...
PSST_TURNSTILE_SECRET_KEY=...
```

3. Lance ensuite :

```bash
make deploy
```

Cette cible :

- compile un binaire release compatible Alpine via musl ;
- copie `target/x86_64-unknown-linux-musl/release/psst-rs` vers `ansible/files/bin/psst-rs` ;
- applique Terraform ;
- lance le playbook Ansible.

Tu peux aussi executer les etapes separement :

```bash
make terraform-apply
make ansible-deploy
```

Ou, pour recompiler et redeployer sans repasser par Terraform :

```bash
make deploy-no-terraform
```

Le fichier `.env` est ignore par Git. Le depot ne doit contenir que `.env.example` avec des placeholders.

Le build de deploiement passe par Docker pour produire un binaire `x86_64-unknown-linux-musl`, adapte a Alpine.

## Execution manuelle

```bash
cd ansible
ansible-playbook site.yml --ask-become-pass
```

## Personnalisation

Les variables principales sont dans `group_vars/all.yml` :

- domaine public ;
- chemin du healthcheck ;
- chemins de deploiement ;
- variables d'environnement de l'application ;
- chemins des certificats TLS ;
- resolvers DNS IPv6 pour les hotes IPv6-only.

Par defaut, le playbook ecrit `/etc/resolv.conf` avec les resolvers definis dans `psst_resolv_nameservers` avant meme le bootstrap Python. Cela evite les echecs `apk` sur une VM IPv6-only qui aurait encore des DNS IPv4.

Tu peux desactiver ce comportement avec :

```yaml
psst_manage_resolv_conf: false
```

## Turnstile

Le frontend et l'API attendent maintenant de vraies cles Turnstile:

- `SECRET_RS_TURNSTILE_SITE_KEY` cote application ;
- `SECRET_RS_TURNSTILE_SECRET_KEY` cote verification serveur.

Le playbook lit par defaut `PSST_TURNSTILE_SITE_KEY` et `PSST_TURNSTILE_SECRET_KEY` depuis l'environnement du controleur Ansible. Tu peux aussi surcharger `psst_turnstile_site_key` et `psst_turnstile_secret_key` via Ansible Vault.

Si `psst_enable_create: true`, le playbook echoue tant que ces deux valeurs ne sont pas definies.

Le service OpenRC lance `psst-rs` via un petit wrapper shell qui source explicitement `{{ psst_env_file | default('/etc/psst-rs/psst-rs.env') }}` avant d'exec le binaire. Cela evite les ambiguïtés de chargement d'environnement avec `openrc-run`.

## Smoke test post-deploiement

Apres avoir applique les changements et vide les handlers en attente, le playbook verifie automatiquement deux chemins :

- l'application directement sur `http://{{ psst_bind_addr | default('127.0.0.1:3000') }}{{ psst_healthcheck_path | default('/healthz') }}` ;
- nginx en local sur `https://127.0.0.1{{ psst_healthcheck_path | default('/healthz') }}` avec l'en-tete `Host: {{ psst_domain | default('psst.example.com') }}`.

Le second test valide le chainage `nginx -> psst-rs` sans dependre d'un hairpin DNS ni de Cloudflare. La verification TLS est volontairement desactivee pour ce test local car le certificat Origin CA installe sur la VM n'est pas une chaine publique faite pour etre verifiee directement par le serveur lui-meme.
