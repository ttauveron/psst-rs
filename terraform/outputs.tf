output "cloudflare_origin_ca_certificate_pem" {
  description = "Cloudflare Origin CA certificate PEM for nginx."
  value       = try(cloudflare_origin_ca_certificate.main[0].certificate, null)
  sensitive   = true
}

output "cloudflare_origin_ca_private_key_pem" {
  description = "Private key PEM matching the Cloudflare Origin CA certificate."
  value       = try(tls_private_key.cloudflare_origin_ca[0].private_key_pem, null)
  sensitive   = true
}

output "cloudflare_origin_ca_expires_on" {
  description = "Expiration date of the Cloudflare Origin CA certificate."
  value       = try(cloudflare_origin_ca_certificate.main[0].expires_on, null)
}
