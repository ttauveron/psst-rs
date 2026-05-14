# OpenTofu / Scaleway + Cloudflare

Cette configuration gere:

- la VM Scaleway existante ;
- le security group de la VM ;
- en option, la couche Cloudflare minimale pour le DNS et le certificat Origin CA.

## Ressources actuellement gerees

- serveur Scaleway `scw-festive-noether` (`8aa55fa0-c312-463e-a39b-aca4ef53798a`)
- security group dedie de la VM
- ranges IPv6 Cloudflare pour le filtrage reseau
- en option:
  - record DNS `AAAA` proxifie dans Cloudflare ;
  - certificat Cloudflare Origin CA pour le hostname public

## Commandes utiles

```bash
cd terraform
tofu init
tofu validate
tofu plan
```

## Cloudflare

La partie Cloudflare est desactivee par defaut avec `cloudflare_enabled = false`.

Quand elle est activee, Terraform gere:

- un record `AAAA` proxifie dans Cloudflare ;
- un certificat Origin CA couvrant le hostname public ;
- la cle privee locale associee au certificat.

Le hostname public est deduit d'une seule variable:

- `cloudflare_hostname`

Cette valeur sert a la fois pour:

- le record DNS Cloudflare ;
- le certificat Origin CA.

L'adresse IPv6 du record `AAAA` n'est pas renseignee a la main: elle est derivee automatiquement de l'IPv6 publique de `scaleway_instance_server.main`.

### Activation

1. Copie `cloudflare.auto.tfvars.example` vers `cloudflare.auto.tfvars`.
2. Renseigne au minimum:
   - `cloudflare_zone_id`
   - `cloudflare_hostname`
3. Exporte les credentials Cloudflare avant `plan` ou `apply`:

```bash
export CLOUDFLARE_API_TOKEN="..."
export CLOUDFLARE_API_USER_SERVICE_KEY="..."
```

Exemple minimal:

```hcl
cloudflare_enabled  = true
cloudflare_zone_id  = "your-zone-id"
cloudflare_hostname = "psst.example.com"
```

### Notes importantes

- `CLOUDFLARE_API_USER_SERVICE_KEY` reste necessaire pour l'API Origin CA.
- Si des ressources Cloudflare existent deja dans le state, `tofu plan` doit quand meme avoir les credentials Cloudflare pour pouvoir faire le refresh.
- La cle privee Origin CA se retrouve dans le state Terraform. Il faut donc proteger ce state ou utiliser un backend chiffre avant usage en production.
- Le record DNS applicatif cree est un `AAAA` proxifie par Cloudflare, adapte a la VM IPv6-only actuelle.

### Sorties utiles

- `cloudflare_origin_ca_certificate_pem`
- `cloudflare_origin_ca_private_key_pem`
- `cloudflare_origin_ca_expires_on`

Exemple pour recuperer les artefacts nginx:

```bash
tofu output -raw cloudflare_origin_ca_certificate_pem > /tmp/origin.crt
tofu output -raw cloudflare_origin_ca_private_key_pem > /tmp/origin.key
```

## Turnstile

Turnstile n'est plus gere par Terraform dans ce depot.

Creation manuelle recommandee dans Cloudflare:

- creer un widget Turnstile pour `cloudflare_hostname` ;
- recuperer le `sitekey` pour le frontend ;
- recuperer le `secret` pour la verification serveur ;
- stocker le `secret` hors Git, par exemple via Ansible Vault ou une variable d'environnement au deploiement.

## Reseau Cloudflare

Les CIDR IPv6 Cloudflare ne sont plus codes en dur. Terraform les recupere depuis l'API officielle Cloudflare:

- `https://api.cloudflare.com/client/v4/ips`

Documentation utile:

- `https://www.cloudflare.com/ips-v6/`
- `https://developers.cloudflare.com/api/resources/ips/`

Effet pratique: au prochain `tofu plan` ou `tofu apply`, si Cloudflare publie un changement de ranges IPv6, Terraform detectera le diff et proposera la mise a jour du security group.
