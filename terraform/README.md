# OpenTofu / Scaleway + Cloudflare

This configuration manages:

- the existing Scaleway VM;
- the VM security group;
- optionally, the minimal Cloudflare layer for DNS and the Origin CA certificate.

## Resources currently managed

- Scaleway server `scw-festive-noether` (`8aa55fa0-c312-463e-a39b-aca4ef53798a`)
- dedicated VM security group
- Cloudflare IPv6 ranges for network filtering
- optionally:
  - proxied `AAAA` DNS record in Cloudflare;
  - Cloudflare Origin CA certificate for the public hostname

## Useful commands

```bash
cd terraform
tofu init
tofu validate
tofu plan
```

## Cloudflare

The Cloudflare part is disabled by default with `cloudflare_enabled = false`.

When enabled, Terraform manages:

- a proxied `AAAA` record in Cloudflare;
- an Origin CA certificate covering the public hostname;
- the local private key associated with the certificate.

The public hostname is derived from a single variable:

- `cloudflare_hostname`

This value is used for both:

- the Cloudflare DNS record;
- the Origin CA certificate.

The IPv6 address of the `AAAA` record is not entered manually: it is automatically derived from the public IPv6 of `scaleway_instance_server.main`.

### Enabling it

1. Copy `cloudflare.auto.tfvars.example` to `cloudflare.auto.tfvars`.
2. Fill in at least:
   - `cloudflare_zone_id`
   - `cloudflare_hostname`
3. Export the Cloudflare credentials before `plan` or `apply`:

```bash
export CLOUDFLARE_API_TOKEN="..."
export CLOUDFLARE_API_USER_SERVICE_KEY="..."
```

Minimal example:

```hcl
cloudflare_enabled  = true
cloudflare_zone_id  = "your-zone-id"
cloudflare_hostname = "psst.example.com"
```

### Important notes

- `CLOUDFLARE_API_USER_SERVICE_KEY` is still required for the Origin CA API.
- If Cloudflare resources already exist in the state, `tofu plan` still needs the Cloudflare credentials so it can refresh them.
- The Origin CA private key ends up in the Terraform state. You should therefore protect that state or use an encrypted backend before production use.
- The application DNS record that gets created is a Cloudflare-proxied `AAAA` record, suitable for the current IPv6-only VM.

### Useful outputs

- `cloudflare_origin_ca_certificate_pem`
- `cloudflare_origin_ca_private_key_pem`
- `cloudflare_origin_ca_expires_on`

Example to retrieve the nginx artifacts:

```bash
tofu output -raw cloudflare_origin_ca_certificate_pem > /tmp/origin.crt
tofu output -raw cloudflare_origin_ca_private_key_pem > /tmp/origin.key
```

## Turnstile

Turnstile is no longer managed by Terraform in this repository.

Recommended manual creation in Cloudflare:

- create a Turnstile widget for `cloudflare_hostname`;
- retrieve the `sitekey` for the frontend;
- retrieve the `secret` for server-side verification;
- store the `secret` outside Git, for example via Ansible Vault or an environment variable at deployment time.

## Cloudflare network

Cloudflare IPv6 CIDRs are no longer hardcoded. Terraform retrieves them from the official Cloudflare API:

- `https://api.cloudflare.com/client/v4/ips`

Useful documentation:

- `https://www.cloudflare.com/ips-v6/`
- `https://developers.cloudflare.com/api/resources/ips/`

Practical effect: on the next `tofu plan` or `tofu apply`, if Cloudflare publishes a change to its IPv6 ranges, Terraform will detect the diff and propose an update to the security group.
