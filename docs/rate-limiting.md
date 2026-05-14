# Rate Limiting

## Resume

`psst-rs` applique un rate limiting applicatif en plus de Cloudflare Turnstile.

Limites actuelles par IP hashée :

- creation : `5` par minute ;
- creation : `30` par heure ;
- lecture : `60` par minute.

Ces valeurs sont configurables par variables d'environnement.

## Variables de configuration

- `SECRET_RS_IP_HASH_SALT`
  Sel serveur obligatoire utilise pour pseudonymiser l'IP cliente avant stockage ou comptage.

- `SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE`
  Limite de creation par minute. Defaut : `5`.

- `SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR`
  Limite de creation par heure. Defaut : `30`.

- `SECRET_RS_READ_RATE_LIMIT_PER_MINUTE`
  Limite souple de lecture par minute. Defaut : `60`.

## Cle de comptage

Le comptage ne stocke jamais l'IP brute.

Le serveur :

- extrait l'IP cliente via les proxies de confiance ;
- calcule un identifiant pseudonymise a partir de l'IP et de `SECRET_RS_IP_HASH_SALT` ;
- utilise cet identifiant comme cle logique pour les buckets de rate limit.

Les secrets eux-memes conservent aussi `requester_ip_hash` en base pour les usages anti-abus futurs.

## Buckets stockes

Les compteurs sont persistés dans SQLite, dans la table `rate_limits`.

Buckets actuels :

- `create-minute:<ip-hash>`
- `create-hour:<ip-hash>`
- `read-minute:<ip-hash>`

Le comptage est donc persistant entre redemarrages du service.

## Reponses HTTP

- `429 Too Many Requests`
  Retourne quand une limite IP est depassee.

- `503 Service Unavailable`
  Retourne pour les indisponibilites globales, par exemple :
  - creation desactivee ;
  - quota global de secrets actifs depasse ;
  - quota global de stockage depasse ;
  - indisponibilite du service de verification Turnstile.

## Notes d'implementation

- Les tentatives de creation sont comptees avant la verification Turnstile finale. Des soumissions invalides ou abusives consomment donc aussi le budget de creation.
- Si aucune IP cliente exploitable n'est disponible dans la requete, les limites IP ne s'appliquent pas.
- La purge automatique des vieux buckets n'est pas encore documentee comme completement finalisee ; les primitives SQLite existent deja pour preparer cette etape.
