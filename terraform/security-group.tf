data "http" "cloudflare_ips" {
  url = "https://api.cloudflare.com/client/v4/ips"

  request_headers = {
    Accept = "application/json"
  }
}

locals {
  cloudflare_ips_payload = jsondecode(data.http.cloudflare_ips.response_body)
  cloudflare_ipv6_ranges = local.cloudflare_ips_payload.result.ipv6_cidrs

  cloudflare_web_ports = [80, 443]

  cloudflare_inbound_rules = flatten([
    for cidr in local.cloudflare_ipv6_ranges : [
      for port in local.cloudflare_web_ports : {
        cidr = cidr
        port = port
      }
    ]
  ])

  ssh_admin_cidrs = [
    "85.2.222.162/32",
    "2a02:1210:2e12:5600:1b70:4a42:b1fe:da5e/128",
  ]
}

resource "scaleway_instance_security_group" "main" {
  name                    = "psst-main"
  description             = "Dedicated security group for the psst VM."
  zone                    = var.zone
  stateful                = true
  enable_default_security = true
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"

  dynamic "inbound_rule" {
    for_each = local.cloudflare_inbound_rules

    content {
      action   = "accept"
      protocol = "TCP"
      port     = inbound_rule.value.port
      ip_range = inbound_rule.value.cidr
    }
  }

  dynamic "inbound_rule" {
    for_each = local.ssh_admin_cidrs

    content {
      action   = "accept"
      protocol = "TCP"
      port     = 22
      ip_range = inbound_rule.value
    }
  }
}
