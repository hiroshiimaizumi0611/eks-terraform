variable "aws_region" {
  description = "AWS Region"
  default     = "ap-northeast-1"
}

variable "cluster_name" {
  description = "EKS Cluster name"
  default     = "moop-eks"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  default     = "10.1.0.0/16"
}

variable "oracle_db_password" {
  description = "Master password for Oracle DB"
  type        = string
  sensitive   = true
}
