# OpenTofu / Scaleway

Cette configuration sert d'abord a reprendre sous gestion la VM Scaleway existante.

## Ressource importee

- serveur `scw-festive-noether` (`8aa55fa0-c312-463e-a39b-aca4ef53798a`)

## Commandes utiles

```bash
cd terraform
tofu init
tofu plan
```

## Reseau Cloudflare

Les CIDR IPv6 Cloudflare ne sont plus codes en dur. Terraform les recupere depuis l'API officielle Cloudflare:

- `https://api.cloudflare.com/client/v4/ips`

Cloudflare documente aussi la liste et son endpoint ici:

- `https://www.cloudflare.com/ips-v6/`
- `https://developers.cloudflare.com/api/resources/ips/`

Effet pratique: au prochain `tofu plan` ou `tofu apply`, si Cloudflare publie un changement de ranges IPv6, Terraform detectera le diff et proposera la mise a jour du security group.
