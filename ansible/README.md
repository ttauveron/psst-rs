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

```bash
cd ansible
ansible-playbook site.yml --ask-become-pass
```

## Personnalisation

Les variables principales sont dans `group_vars/all.yml` :

- domaine public ;
- chemins de deploiement ;
- variables d'environnement de l'application ;
- chemins des certificats TLS.
