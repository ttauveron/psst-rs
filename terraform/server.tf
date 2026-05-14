resource "scaleway_instance_server" "main" {
  name              = "scw-festive-noether"
  type              = "STARDUST1-S"
  image             = "fr-par-1/6d67b263-ecc3-4d29-87af-d3b3ee29e5d4"
  state             = "started"
  zone              = var.zone
  boot_type         = "local"
  enable_dynamic_ip = false
  protected         = false
  security_group_id = scaleway_instance_security_group.main.id

  root_volume {
    name                  = "scw-festive-noether-system"
    size_in_gb            = 10
    volume_type           = "l_ssd"
    delete_on_termination = true
  }
}
