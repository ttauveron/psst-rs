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

Quand on ajoutera les regles inbound/outbound, il sera preferable de basculer vers un security group dedie plutot que de modifier le security group par defaut du projet.
