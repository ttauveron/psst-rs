# Ansible

Structure minimale pour deployer `psst-rs` sur une VM Alpine avec OpenRC et nginx.

## Artefacts locaux a fournir

- `files/bin/psst-rs` : binaire Rust deja compile pour la VM cible
- `files/tls/origin.crt` : certificat TLS
- `files/tls/origin.key` : cle privee TLS

Ces fichiers sont ignores par Git. Pour la cle TLS, prefere un fichier hors repo ou Ansible Vault.

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
