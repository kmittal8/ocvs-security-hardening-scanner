variable "tenancy_ocid" {
  description = "OCI tenancy OCID"
  type        = string
}

variable "user_ocid" {
  description = "OCI user OCID used for API calls"
  type        = string
}

variable "compartment_ocid" {
  description = "Compartment OCID where resources will be created"
  type        = string
}

variable "region" {
  description = "OCI region (e.g., ap-melbourne-1)"
  type        = string
}

variable "api_fingerprint" {
  description = "Fingerprint of the OCI API key"
  type        = string
}

variable "api_private_key_path" {
  description = "Path to the OCI API private key (e.g., /Users/kay/.oci/oci_api_key.pem)"
  type        = string
}

variable "vm_shape" {
  description = "Compute shape (e.g., VM.Standard3.Flex)"
  type        = string
}

variable "vm_ocpus" {
  description = "Number of OCPUs for flex shapes"
  type        = number
  default     = 2
}

variable "vm_memory_in_gbs" {
  description = "Memory (GB) for flex shapes"
  type        = number
  default     = 16
}

variable "vm_boot_volume_size_in_gbs" {
  description = "Boot volume size in GB"
  type        = number
  default     = 100
}

variable "vm_image_ocid" {
  description = "Optional explicit image OCID"
  type        = string
  default     = ""
}

variable "target_vcn_ocid" {
  description = "Existing VCN OCID where the scanner VM should be placed"
  type        = string
}

variable "target_subnet_ocid" {
  description = "Existing subnet OCID for the scanner VM VNIC"
  type        = string
}