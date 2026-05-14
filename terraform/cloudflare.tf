locals {
  cloudflare_origin_enabled      = var.cloudflare_enabled
  cloudflare_dns_enabled         = var.cloudflare_enabled
  cloudflare_hostname            = trimspace(var.cloudflare_hostname)
  cloudflare_origin_hostnames    = [local.cloudflare_hostname]
  cloudflare_origin_common_name  = local.cloudflare_hostname
  cloudflare_origin_ipv6_address = scaleway_instance_server.main.public_ips[0].address
}

resource "terraform_data" "cloudflare_inputs" {
  count = var.cloudflare_enabled ? 1 : 0

  input = {
    zone_id         = var.cloudflare_zone_id
    hostname        = local.cloudflare_hostname
    origin_hostname = local.cloudflare_origin_hostnames
  }

  lifecycle {
    precondition {
      condition     = var.cloudflare_zone_id != null && trimspace(var.cloudflare_zone_id) != ""
      error_message = "cloudflare_zone_id must be set when cloudflare_enabled is true."
    }

    precondition {
      condition     = local.cloudflare_hostname != ""
      error_message = "cloudflare_hostname must not be empty when cloudflare_enabled is true."
    }

    precondition {
      condition     = can(scaleway_instance_server.main.public_ips[0].address) && trimspace(scaleway_instance_server.main.public_ips[0].address) != ""
      error_message = "The Scaleway server must expose a public IPv6 address to create the Cloudflare AAAA record."
    }
  }
}

resource "tls_private_key" "cloudflare_origin_ca" {
  count = local.cloudflare_origin_enabled ? 1 : 0

  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "cloudflare_origin_ca" {
  count = local.cloudflare_origin_enabled ? 1 : 0

  private_key_pem = tls_private_key.cloudflare_origin_ca[0].private_key_pem
  dns_names       = local.cloudflare_origin_hostnames

  subject {
    common_name = local.cloudflare_origin_common_name
  }
}

resource "cloudflare_origin_ca_certificate" "main" {
  count = local.cloudflare_origin_enabled ? 1 : 0

  csr                = tls_cert_request.cloudflare_origin_ca[0].cert_request_pem
  hostnames          = local.cloudflare_origin_hostnames
  request_type       = "origin-ecc"
  requested_validity = var.cloudflare_origin_certificate_validity_days
}

resource "cloudflare_dns_record" "app_ipv6" {
  count = local.cloudflare_dns_enabled ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = local.cloudflare_hostname
  type    = "AAAA"
  content = local.cloudflare_origin_ipv6_address
  proxied = var.cloudflare_dns_record_proxied
  ttl     = 1
}
