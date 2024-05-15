resource "keyfactor_certificate" "pfx_enrollment_01" {
  common_name           = "K8S PFX Enrollment Certificate"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}