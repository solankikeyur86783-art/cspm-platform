# ─────────────────────────────────────────────────────────────────────────────
# CSPM Lab — Terraform
# Creates ALL 17 AWS resources with intentional misconfigurations for testing.
# Region: ap-south-1 (Mumbai)
# Run:  terraform init → terraform plan → terraform apply
# Done: terraform destroy  (delete everything)
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CSPM-Lab"
      Environment = "lab"
      ManagedBy   = "Terraform"
      Owner       = var.owner_name
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

resource "random_id" "suffix" { byte_length = 4 }

locals {
  account_id = data.aws_caller_identity.current.account_id
  az_a       = data.aws_availability_zones.available.names[0]
  az_b       = data.aws_availability_zones.available.names[1]
  suffix     = random_id.suffix.hex
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 — VPC
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_vpc" "cspm_lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "CSPM-LAB" }
}

# STEP 4 — Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.cspm_lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = local.az_a
  map_public_ip_on_launch = true     # ← intentional: auto-assigns public IPs

  tags = { Name = "CSPM-Public", Type = "public" }
}

# STEP 4 — Private Subnet
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.cspm_lab.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = local.az_b

  tags = { Name = "CSPM-Private", Type = "private" }
}

# Subnet for RDS (needs 2 AZs)
resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.cspm_lab.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = local.az_b

  tags = { Name = "CSPM-Private-B" }
}

# STEP 5 — Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.cspm_lab.id
  tags   = { Name = "CSPM-IGW" }
}

# STEP 6 — Route Table (public)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cspm_lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "CSPM-Public-RT" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 7 — Security Groups (INTENTIONAL MISCONFIGURATIONS)
# ═════════════════════════════════════════════════════════════════════════════

# SG-Linux: SSH open to world (CIS-EC2-5.2 — HIGH finding)
resource "aws_security_group" "sg_linux" {
  name        = "SG-Linux-${local.suffix}"
  description = "CSPM Lab: Linux SG with open SSH"
  vpc_id      = aws_vpc.cspm_lab.id

  # ← MISCONFIGURATION: SSH open to 0.0.0.0/0
  ingress {
    description = "SSH open to internet (intentional misconfiguration)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "SG-Linux", Misconfiguration = "open-ssh" }
}

# SG-Windows: RDP open to world (CIS-EC2-5.3 — CRITICAL finding)
resource "aws_security_group" "sg_windows" {
  name        = "SG-Windows-${local.suffix}"
  description = "CSPM Lab: Windows SG with open RDP"
  vpc_id      = aws_vpc.cspm_lab.id

  # ← MISCONFIGURATION: RDP open to 0.0.0.0/0
  ingress {
    description = "RDP open to internet (intentional misconfiguration)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "SG-Windows", Misconfiguration = "open-rdp" }
}

# SG for RDS
resource "aws_security_group" "sg_rds" {
  name        = "SG-RDS-${local.suffix}"
  description = "CSPM Lab: RDS SG"
  vpc_id      = aws_vpc.cspm_lab.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # ← also misconfigured
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "SG-RDS" }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 8 — Linux EC2 (Amazon Linux 2023, t2.micro)
# ═════════════════════════════════════════════════════════════════════════════
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "linux_test" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.sg_linux.id]

  # ← MISCONFIGURATION: IMDSv1 allowed (EC2-IMDS-001 — HIGH finding)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"   # should be "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 8
    encrypted   = false   # ← MISCONFIGURATION: EC2-EBS-001 — MEDIUM finding
  }

  tags = { Name = "linux-test", Misconfiguration = "imdsv1-unencrypted" }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 9 — Windows EC2 (optional — can be costly, t2.micro)
# ═════════════════════════════════════════════════════════════════════════════
data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

resource "aws_instance" "windows_test" {
  count                  = var.create_windows_ec2 ? 1 : 0
  ami                    = data.aws_ami.windows.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.sg_windows.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    volume_size = 30
    encrypted   = false
  }

  tags = { Name = "windows-test" }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 10 — S3 Buckets (3 buckets, one public)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_s3_bucket" "private" {
  bucket        = "company-private-${local.suffix}"
  force_destroy = true
  tags          = { Name = "company-private", Access = "private" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  bucket = aws_s3_bucket.private.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# company-public: PUBLIC bucket (CIS-S3-2.1.1 — HIGH finding)
resource "aws_s3_bucket" "public_bucket" {
  bucket        = "company-public-${local.suffix}"
  force_destroy = true
  tags          = { Name = "company-public", Misconfiguration = "public-access" }
}

# ← MISCONFIGURATION: Disable public access block
resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ← MISCONFIGURATION: No encryption (CIS-S3-2.1.2 — MEDIUM finding)
# (Intentionally NOT adding encryption resource)

# company-backup: no versioning, no logging (CIS-S3-2.1.3 — MEDIUM finding)
resource "aws_s3_bucket" "backup" {
  bucket        = "company-backup-${local.suffix}"
  force_destroy = true
  tags          = { Name = "company-backup", Misconfiguration = "no-versioning" }
}

# ← MISCONFIGURATION: No encryption on backup
# ← MISCONFIGURATION: No versioning on backup

# ═════════════════════════════════════════════════════════════════════════════
# STEP 11 — IAM Users (developer with admin access — CRITICAL finding)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_iam_user" "developer" {
  name = "developer-${local.suffix}"
  tags = { Role = "developer", Misconfiguration = "admin-access" }
}

# ← MISCONFIGURATION: AdministratorAccess directly on user (CIS-IAM-1.16)
resource "aws_iam_user_policy_attachment" "developer_admin" {
  user       = aws_iam_user.developer.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "intern" {
  name = "intern-${local.suffix}"
  tags = { Role = "intern" }
}

resource "aws_iam_user_policy_attachment" "intern_readonly" {
  user       = aws_iam_user.intern.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user" "admin_user" {
  name = "admin-${local.suffix}"
  tags = { Role = "admin" }
}

resource "aws_iam_user_policy_attachment" "admin_full" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ← MISCONFIGURATION: Access key for developer (will age beyond 90 days)
resource "aws_iam_access_key" "developer" {
  user = aws_iam_user.developer.name
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 12 — CloudTrail (created then stopped — CRITICAL finding)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cspm-cloudtrail-${local.suffix}"
  force_destroy = true
  tags          = { Name = "cloudtrail-logs" }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "lab" {
  name                          = "cspm-lab-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = false   # ← MISCONFIGURATION: not multi-region (CIS 2.1)
  enable_log_file_validation    = false   # ← MISCONFIGURATION: no log validation (CIS 2.2)
  include_global_service_events = true

  depends_on = [aws_s3_bucket_policy.cloudtrail]
  tags       = { Name = "cspm-lab-trail", Misconfiguration = "not-multi-region" }
}

# ← NOTE: After apply, manually stop logging in AWS Console to simulate
# CIS-CT-2.1-LOGGING (CRITICAL). Or use aws cloudtrail stop-logging CLI.

# ═════════════════════════════════════════════════════════════════════════════
# STEP 14 — EBS Volumes (encrypted + unencrypted)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_ebs_volume" "encrypted" {
  availability_zone = local.az_a
  size              = 1
  encrypted         = true
  type              = "gp3"
  tags              = { Name = "encrypted-vol", Status = "compliant" }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = local.az_a
  size              = 1
  encrypted         = false   # ← MISCONFIGURATION: EC2-EBS-001 — MEDIUM finding
  type              = "gp3"
  tags              = { Name = "unencrypted-vol", Misconfiguration = "no-encryption" }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 15 — RDS MySQL (publicly accessible — HIGH finding)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_db_subnet_group" "lab" {
  name       = "cspm-lab-db-subnet-${local.suffix}"
  subnet_ids = [aws_subnet.private.id, aws_subnet.private_b.id]
  tags       = { Name = "cspm-lab-db-subnet" }
}

resource "aws_db_instance" "public_rds" {
  count                  = var.create_rds ? 1 : 0
  identifier             = "cspm-lab-db-${local.suffix}"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "cspmlab"
  username               = "admin"
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.lab.name
  vpc_security_group_ids = [aws_security_group.sg_rds.id]

  publicly_accessible    = true    # ← MISCONFIGURATION: CIS-RDS-2.3.2 — HIGH
  storage_encrypted      = false   # ← MISCONFIGURATION: CIS-RDS-2.3.1 — HIGH
  backup_retention_period = 0      # ← MISCONFIGURATION: RDS-BACKUP-001 — MEDIUM
  deletion_protection    = false   # ← MISCONFIGURATION: RDS-DEL-001 — MEDIUM
  skip_final_snapshot    = true
  multi_az               = false

  tags = { Name = "cspm-lab-db", Misconfiguration = "public-unencrypted" }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 16 — Lambda with overly permissive role
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_iam_role" "lambda_admin" {
  name = "cspm-lambda-admin-role-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Misconfiguration = "overly-permissive" }
}

# ← MISCONFIGURATION: Lambda has full admin access (should be minimal)
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "test" {
  function_name = "cspm-lab-function-${local.suffix}"
  role          = aws_iam_role.lambda_admin.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 30

  filename         = "${path.module}/lambda_function.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda_function.zip")

  environment {
    variables = {
      ENV = "lab"
    }
  }

  tags = { Name = "cspm-lab-function", Misconfiguration = "admin-role" }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 17 — Secrets Manager (rotation disabled — MEDIUM finding)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "cspm-lab/db-password-${local.suffix}"
  description             = "CSPM Lab: DB password without rotation"
  recovery_window_in_days = 0   # immediate delete on destroy

  tags = { Misconfiguration = "no-rotation" }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = "admin"
    password = var.db_password
    host     = "db.example.com"
    port     = 3306
  })
  # ← MISCONFIGURATION: Rotation intentionally NOT configured (SM-ROTATION-001)
}

# ═════════════════════════════════════════════════════════════════════════════
# CSPM Scanner Role (read-only — for your CSPM platform to use)
# ═════════════════════════════════════════════════════════════════════════════
resource "aws_iam_role" "cspm_scanner" {
  name = "CSPMScannerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
    }]
  })

  tags = { Name = "CSPMScannerRole", Purpose = "read-only-scanner" }
}

resource "aws_iam_role_policy_attachment" "cspm_security_audit" {
  role       = aws_iam_role.cspm_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "cspm_readonly" {
  role       = aws_iam_role.cspm_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
