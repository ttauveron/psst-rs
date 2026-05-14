resource "scaleway_instance_security_group" "main" {
  name                    = "psst-main"
  description             = "Dedicated security group for the psst VM."
  zone                    = var.zone
  stateful                = true
  enable_default_security = true
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
}
