terraform {
  required_version = ">= 1.8.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.19"
    }

    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }

    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.55"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}
