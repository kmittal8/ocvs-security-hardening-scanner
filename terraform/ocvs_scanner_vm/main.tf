terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.5"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.api_fingerprint
  private_key_path = var.api_private_key_path
  region           = var.region
}

resource "random_id" "instance_suffix" {
  byte_length = 3
}

resource "tls_private_key" "scanner" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "oracle_linux" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Oracle Linux"
  operating_system_version = "9"
  shape                    = var.vm_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

locals {
  vm_image_id = var.vm_image_ocid != "" ? var.vm_image_ocid : data.oci_core_images.oracle_linux.images[0].id
}

data "oci_core_vcn" "target" {
  vcn_id = var.target_vcn_ocid
}

resource "oci_core_security_list" "scanner" {
  compartment_id = var.compartment_ocid
  display_name   = "scanner-streamlit-sl"
  vcn_id         = data.oci_core_vcn.target.id

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol = "6" # TCP
    source   = "0.0.0.0/0"

    tcp_options {
      min = 22
      max = 22
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {
      min = 8501
      max = 8501
    }
  }
}

resource "oci_core_instance" "scanner" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "ocvs-scanner-${random_id.instance_suffix.hex}"
  shape               = var.vm_shape

  shape_config {
    ocpus         = var.vm_ocpus
    memory_in_gbs = var.vm_memory_in_gbs
  }

  create_vnic_details {
    assign_private_dns_record = true
    assign_public_ip          = true
    display_name              = "scanner-vnic"
    subnet_id                 = var.target_subnet_ocid
    nsg_ids                   = []
  }

  metadata = {
    ssh_authorized_keys = tls_private_key.scanner.public_key_openssh
  }

  source_details {
    source_type             = "image"
    source_id               = local.vm_image_id
    boot_volume_size_in_gbs = var.vm_boot_volume_size_in_gbs
  }
}

resource "local_file" "ssh_private_key" {
  filename        = "${path.module}/id_rsa_ocvs_scanner.pem"
  content         = tls_private_key.scanner.private_key_pem
  file_permission = "0600"
}

resource "local_file" "ssh_public_key" {
  filename = "${path.module}/id_rsa_ocvs_scanner.pub"
  content  = tls_private_key.scanner.public_key_openssh
}

output "vm_public_ip" {
  value = oci_core_instance.scanner.public_ip
}

output "vm_private_ip" {
  value = oci_core_instance.scanner.private_ip
}

output "ssh_private_key_pem" {
  value     = tls_private_key.scanner.private_key_pem
  sensitive = true
}

output "ssh_public_key_openssh" {
  value = tls_private_key.scanner.public_key_openssh
}