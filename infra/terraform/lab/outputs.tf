output "cspm_scanner_role_arn" {
  description = "Copy this into your CSPM .env as AWS_SCANNER_ROLE_ARN"
  value       = aws_iam_role.cspm_scanner.arn
}

output "vpc_id" {
  value = aws_vpc.cspm_lab.id
}

output "linux_ec2_public_ip" {
  value = aws_instance.linux_test.public_ip
}

output "s3_public_bucket" {
  description = "Public bucket — CSPM should flag this"
  value       = aws_s3_bucket.public_bucket.id
}

output "s3_private_bucket" {
  value = aws_s3_bucket.private.id
}

output "s3_backup_bucket" {
  value = aws_s3_bucket.backup.id
}

output "rds_endpoint" {
  description = "Public RDS endpoint — CSPM should flag this"
  value       = var.create_rds ? aws_db_instance.public_rds[0].endpoint : "RDS not created"
}

output "secret_arn" {
  description = "Secret without rotation — CSPM should flag this"
  value       = aws_secretsmanager_secret.db_password.arn
}

output "developer_access_key_id" {
  description = "IAM access key — will age and trigger CIS-IAM-1.14"
  value       = aws_iam_access_key.developer.id
  sensitive   = true
}

output "lambda_function_name" {
  value = aws_lambda_function.test.function_name
}

output "cloudtrail_name" {
  description = "After apply, stop logging to trigger CIS-CT-2.1-LOGGING"
  value       = aws_cloudtrail.lab.name
}

output "expected_findings_summary" {
  description = "What your CSPM scanner should detect"
  value = <<-EOT

  ╔══════════════════════════════════════════════════════╗
  ║        Expected CSPM Findings After Scan             ║
  ╠══════════════════════════════════════════════════════╣
  ║ CRITICAL  Open RDP (port 3389) to 0.0.0.0/0         ║
  ║ CRITICAL  Root account MFA not enabled               ║
  ║ CRITICAL  CloudTrail logging stopped (manual step)   ║
  ║ HIGH      Open SSH (port 22) to 0.0.0.0/0            ║
  ║ HIGH      AdministratorAccess on IAM user            ║
  ║ HIGH      S3 bucket publicly accessible              ║
  ║ HIGH      RDS instance publicly accessible           ║
  ║ HIGH      RDS storage not encrypted                  ║
  ║ MEDIUM    Unencrypted EBS volume                     ║
  ║ MEDIUM    S3 bucket no server-side encryption        ║
  ║ MEDIUM    S3 bucket no versioning (backup bucket)    ║
  ║ MEDIUM    RDS no backup retention                    ║
  ║ MEDIUM    RDS no deletion protection                 ║
  ║ MEDIUM    Secrets Manager rotation disabled          ║
  ║ MEDIUM    EC2 IMDSv2 not enforced                    ║
  ║ LOW       Access key not rotated (after 90 days)     ║
  ╚══════════════════════════════════════════════════════╝

  Total expected: 16-20+ findings
  EOT
}
