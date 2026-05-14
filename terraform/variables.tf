variable "zone" {
  description = "Scaleway availability zone."
  type        = string
  default     = "fr-par-1"
}

variable "cloudflare_enabled" {
  description = "Enable Cloudflare-managed resources in this stack."
  type        = bool
  default     = false
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID used for zone-scoped resources such as DNS records."
  type        = string
  default     = null
  nullable    = true
}

variable "cloudflare_hostname" {
  description = "Fully qualified hostname exposed through Cloudflare for the application."
  type        = string
  default     = "psst.ttauveron.com"
}

variable "cloudflare_dns_record_proxied" {
  description = "Whether the application DNS record should be proxied by Cloudflare."
  type        = bool
  default     = true
}

variable "cloudflare_origin_certificate_validity_days" {
  description = "Requested validity for the Cloudflare Origin CA certificate."
  type        = number
  default     = 5475
}
