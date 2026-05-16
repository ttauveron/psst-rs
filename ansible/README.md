# Ansible

Minimal structure to deploy `psst-rs` to an Alpine VM with OpenRC and nginx.

## Local artifacts to provide

- `files/bin/psst-rs`: Rust binary already compiled for the target VM
- `files/tls/origin.crt`: TLS certificate
- `files/tls/origin.key`: TLS private key

These files are ignored by Git. For the TLS key, prefer a file outside the repository or Ansible Vault.

## Terraform integration

By default, the playbook tries to read Terraform outputs from `../terraform` to automatically retrieve:

- `cloudflare_hostname`
- `cloudflare_origin_ca_certificate_pem`
- `cloudflare_origin_ca_private_key_pem`

When these outputs are available, Ansible:

- derives `psst_domain` and `psst_public_base_url` from Terraform;
- installs the Origin CA certificate and its private key without using `files/tls/*`.

If Terraform is not ready yet or if you want to stay in manual mode, set:

```yaml
psst_use_terraform_outputs: false
```

In that case, Ansible falls back to the original behavior and expects `files/tls/origin.crt` and `files/tls/origin.key`.

## Running

The simplest workflow for a home lab uses the `Makefile` at the repository root.

1. Create a `.env` file at the root from `.env.example`.
2. Fill it with:

```dotenv
CLOUDFLARE_API_TOKEN=...
PSST_TURNSTILE_SITE_KEY=...
PSST_TURNSTILE_SECRET_KEY=...
```

3. Then run:

```bash
make deploy
```

This target:

- builds an Alpine-compatible release binary via musl;
- copies `target/x86_64-unknown-linux-musl/release/psst-rs` to `ansible/files/bin/psst-rs`;
- applies Terraform;
- runs the Ansible playbook.

You can also run the steps separately:

```bash
make terraform-apply
make ansible-deploy
```

Or, to rebuild and redeploy without going through Terraform again:

```bash
make deploy-no-terraform
```

The `.env` file is ignored by Git. The repository should only contain `.env.example` with placeholders.

The deployment build goes through Docker to produce an `x86_64-unknown-linux-musl` binary suitable for Alpine.

## Manual run

```bash
cd ansible
ansible-playbook site.yml --ask-become-pass
```

## Customization

The main variables are in `group_vars/all.yml`:

- public domain;
- healthcheck path;
- deployment paths;
- application environment variables;
- TLS certificate paths;
- IPv6 DNS resolvers for IPv6-only hosts.

By default, the playbook writes `/etc/resolv.conf` with the resolvers defined in `psst_resolv_nameservers` even before Python bootstrap. This avoids `apk` failures on an IPv6-only VM that still has IPv4 DNS configured.

You can disable this behavior with:

```yaml
psst_manage_resolv_conf: false
```

## Turnstile

The frontend and API now expect real Turnstile keys:

- `PSST_RS_TURNSTILE_SITE_KEY` on the application side;
- `PSST_RS_TURNSTILE_SECRET_KEY` for server-side verification.

By default, the playbook reads `PSST_TURNSTILE_SITE_KEY` and `PSST_TURNSTILE_SECRET_KEY` from the Ansible controller environment. You can also override `psst_turnstile_site_key` and `psst_turnstile_secret_key` via Ansible Vault.

If `psst_enable_create: true`, the playbook fails until both values are defined.

The OpenRC service starts `psst-rs` through a small shell wrapper that explicitly sources `{{ psst_env_file | default('/etc/psst-rs/psst-rs.env') }}` before executing the binary. This avoids environment-loading ambiguity with `openrc-run`.

## Post-deployment smoke test

After applying changes and flushing pending handlers, the playbook automatically checks two paths:

- the application directly at `http://{{ psst_bind_addr | default('127.0.0.1:3000') }}{{ psst_healthcheck_path | default('/healthz') }}`;
- nginx locally at `https://127.0.0.1{{ psst_healthcheck_path | default('/healthz') }}` with the `Host: {{ psst_domain | default('psst.example.com') }}` header.

The second test validates the `nginx -> psst-rs` chain without depending on hairpin DNS or Cloudflare. TLS verification is intentionally disabled for this local test because the Origin CA certificate installed on the VM is not a public chain meant to be verified directly by the server itself.
