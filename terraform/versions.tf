terraform {
  required_version = ">= 1.8.0"

  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }

    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.55"
    }
  }
}
