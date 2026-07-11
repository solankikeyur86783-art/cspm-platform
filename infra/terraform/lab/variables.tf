variable "aws_region" {
  description = "AWS region for lab resources"
  type        = string
  default     = "ap-south-1"   # Mumbai — closest to India
}

variable "owner_name" {
  description = "Your name (for resource tags)"
  type        = string
  default     = "cspm-student"
}

variable "db_password" {
  description = "Password for RDS and Secrets Manager"
  type        = string
  sensitive   = true
  default     = "Lab@Pass123!"
}

variable "create_rds" {
  description = "Set false to skip RDS (saves ~$0.017/hr)"
  type        = bool
  default     = true
}

variable "create_windows_ec2" {
  description = "Set false to skip Windows EC2 (saves cost)"
  type        = bool
  default     = false   # Windows EC2 costs more, disable by default
}
