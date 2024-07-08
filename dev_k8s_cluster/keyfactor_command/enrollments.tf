resource "keyfactor_certificate" "pfx_enrollment_00" {
  common_name           = "K8S PFX Enrollment Certificate 01"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate 00"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}

resource "keyfactor_certificate" "pfx_enrollment_01" {
  common_name           = "K8S PFX Enrollment Certificate 01"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate 01"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}

resource "keyfactor_certificate" "pfx_enrollment_02" {
  common_name           = "K8S PFX Enrollment Certificate 02"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate 02"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}

resource "keyfactor_certificate" "pfx_enrollment_03" {
  common_name           = "K8S PFX Enrollment Certificate 03"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate 03"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}

resource "keyfactor_certificate" "pfx_enrollment_04" {
  common_name           = "K8S PFX Enrollment Certificate 04"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate 04"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}

resource "keyfactor_certificate" "pfx_enrollment_05" {
  common_name           = "K8S PFX Enrollment Certificate"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  dns_sans              = ["K8S PFX Enrollment Certificate 05"]
  // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "${var.default_ca_domain}\\${var.default_cert_ca}"
  certificate_template  = var.webserver_template
  metadata              = {
    "Email-Contact" = "terraform@example.com"
  }
}