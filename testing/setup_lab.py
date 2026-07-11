"""
lab_setup.py — Creates all 10 intentionally misconfigured AWS resources
for real-world CSPM testing.

SAFE TO RUN: Only creates resources in YOUR AWS account.
Run cleanup.py after testing to delete everything.

Usage:
    python lab_setup.py --region us-east-1
    python lab_setup.py --region us-east-1 --dry-run   # Preview only
"""

import boto3
import json
import time
import argparse
import sys
from datetime import datetime


# ── Resource name prefix (easy to find & delete) ─────────────────────────────
PREFIX = "cspm-lab"
TIMESTAMP = datetime.now().strftime("%Y%m%d%H%M")


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")


def print_step(num, text):
    print(f"\n[Scenario {num}] {text}")


def print_ok(text):
    print(f"  ✅  {text}")


def print_warn(text):
    print(f"  ⚠️   {text}")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Public S3 Bucket  (Expected: HIGH)
# ═══════════════════════════════════════════════════════════════════════════════
def create_public_s3_bucket(s3, region):
    print_step(1, "Public S3 Bucket — CIS 2.1.1 / MITRE T1530")
    bucket_name = f"{PREFIX}-public-bucket-{TIMESTAMP}"

    kwargs = {"Bucket": bucket_name}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)

    # Disable block public access (creates the vulnerability)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    # Make bucket public via ACL
    s3.put_bucket_acl(Bucket=bucket_name, ACL="public-read")

    # Upload a dummy file so there's evidence
    s3.put_object(
        Bucket=bucket_name,
        Key="README.txt",
        Body=b"This bucket is intentionally public for CSPM lab testing.",
    )

    print_ok(f"Created public bucket: {bucket_name}")
    return bucket_name


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — Security Group: SSH open to 0.0.0.0/0  (Expected: HIGH)
# ═══════════════════════════════════════════════════════════════════════════════
def create_open_ssh_sg(ec2, vpc_id):
    print_step(2, "Open SSH Security Group — CIS 5.2 / MITRE T1190")
    sg = ec2.create_security_group(
        GroupName=f"{PREFIX}-open-ssh-sg-{TIMESTAMP}",
        Description="CSPM Lab: SG with SSH open to internet",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "CSPM lab - open SSH"}],
            }
        ],
    )
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "Name", "Value": f"{PREFIX}-open-ssh"}])
    print_ok(f"Created open-SSH security group: {sg_id}")
    return sg_id


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Security Group: RDP open to 0.0.0.0/0  (Expected: CRITICAL)
# ═══════════════════════════════════════════════════════════════════════════════
def create_open_rdp_sg(ec2, vpc_id):
    print_step(3, "Open RDP Security Group — CIS 5.3 / MITRE T1021.001")
    sg = ec2.create_security_group(
        GroupName=f"{PREFIX}-open-rdp-sg-{TIMESTAMP}",
        Description="CSPM Lab: SG with RDP open to internet",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "CSPM lab - open RDP"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "Name", "Value": f"{PREFIX}-open-rdp"}])
    print_ok(f"Created open-RDP security group: {sg_id}")
    return sg_id


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — IAM User with AdministratorAccess  (Expected: CRITICAL)
# ═══════════════════════════════════════════════════════════════════════════════
def create_admin_iam_user(iam):
    print_step(4, "IAM User with AdministratorAccess — CIS 1.16 / MITRE T1078.004")
    user_name = f"{PREFIX}-admin-user-{TIMESTAMP}"

    iam.create_user(UserName=user_name)
    iam.attach_user_policy(
        UserName=user_name,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    # Also create a console login profile (no MFA = another finding)
    iam.create_login_profile(
        UserName=user_name,
        Password="Temp@Lab123!",
        PasswordResetRequired=True,
    )

    print_ok(f"Created admin IAM user: {user_name}")
    print_warn("AdministratorAccess directly attached to user (CIS 1.16)")
    return user_name


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 5 — Root account MFA check (Expected: CRITICAL)
# NOTE: Cannot programmatically disable root MFA. We check if it's missing.
# ═══════════════════════════════════════════════════════════════════════════════
def check_root_mfa(iam):
    print_step(5, "Root Account MFA — CIS 1.5 / MITRE T1078.004")
    try:
        summary = iam.get_account_summary()
        mfa_enabled = summary["SummaryMap"].get("AccountMFAEnabled", 0)
        if mfa_enabled:
            print_warn("Root MFA is already enabled — CSPM should report PASS")
            print_warn("To test: disable root MFA in AWS Console → Security Credentials")
        else:
            print_ok("Root MFA NOT enabled — CSPM should report CRITICAL finding")
    except Exception as e:
        print_warn(f"Could not check root MFA: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 6 — Disable CloudTrail  (Expected: CRITICAL)
# ═══════════════════════════════════════════════════════════════════════════════
def disable_cloudtrail(ct, region):
    print_step(6, "Disable CloudTrail — CIS 2.1 / MITRE T1562.008")
    # Create a trail first, then stop logging
    bucket_name = f"{PREFIX}-ct-bucket-{TIMESTAMP}"

    s3 = boto3.client("s3", region_name=region)
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )

        # Attach bucket policy required by CloudTrail
        account_id = boto3.client("sts").get_caller_identity()["Account"]
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

        trail = ct.create_trail(
            Name=f"{PREFIX}-disabled-trail-{TIMESTAMP}",
            S3BucketName=bucket_name,
            IsMultiRegionTrail=False,  # Also a finding: not multi-region (CIS 2.1)
        )
        # Stop logging → this is the CRITICAL finding
        ct.stop_logging(Name=trail["TrailARN"])
        print_ok(f"Created CloudTrail trail with logging STOPPED: {trail['TrailARN']}")
        print_ok(f"Trail is also NOT multi-region (second finding: CIS 2.1)")
        return trail["TrailARN"], bucket_name
    except Exception as e:
        print_warn(f"CloudTrail setup skipped: {e}")
        return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 7 — Unencrypted EBS Volume  (Expected: MEDIUM)
# ═══════════════════════════════════════════════════════════════════════════════
def create_unencrypted_ebs(ec2, az):
    print_step(7, "Unencrypted EBS Volume — CIS 2.2.1 / MITRE T1005")
    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        Encrypted=False,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": f"{PREFIX}-unencrypted-vol"},
                    {"Key": "Purpose", "Value": "CSPM Lab Testing"},
                ],
            }
        ],
    )
    print_ok(f"Created unencrypted EBS volume: {vol['VolumeId']} (1 GB, gp3)")
    return vol["VolumeId"]


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 8 — Public RDS Instance  (Expected: HIGH)
# ═══════════════════════════════════════════════════════════════════════════════
def create_public_rds(rds, sg_id, region):
    print_step(8, "Publicly Accessible RDS — CIS 2.3.2 / MITRE T1190")
    try:
        db = rds.create_db_instance(
            DBInstanceIdentifier=f"{PREFIX}-public-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="Lab@Pass123!",
            AllocatedStorage=20,
            PubliclyAccessible=True,        # ← THE VULNERABILITY
            StorageEncrypted=False,          # ← ALSO flagged: CIS 2.3.1
            BackupRetentionPeriod=0,         # ← ALSO flagged: RDS-BACKUP-001
            DeletionProtection=False,        # ← ALSO flagged: RDS-DEL-001
            MultiAZ=False,
            VpcSecurityGroupIds=[sg_id],
            Tags=[
                {"Key": "Name", "Value": f"{PREFIX}-public-rds"},
                {"Key": "Purpose", "Value": "CSPM Lab Testing"},
            ],
        )
        print_ok(f"Creating public RDS instance: {PREFIX}-public-db")
        print_warn("RDS creation takes ~5 minutes — scanner will pick it up when available")
        print_warn("Also generates: CIS 2.3.1 (no encryption), RDS-BACKUP-001 (no backup), RDS-DEL-001 (no deletion protection)")
        return db["DBInstance"]["DBInstanceIdentifier"]
    except rds.exceptions.DBInstanceAlreadyExistsFault:
        print_warn("RDS instance already exists — skipping")
        return f"{PREFIX}-public-db"
    except Exception as e:
        print_warn(f"RDS creation failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 9 — Secrets Manager: rotation disabled  (Expected: MEDIUM)
# ═══════════════════════════════════════════════════════════════════════════════
def create_secret_no_rotation(sm):
    print_step(9, "Secrets Manager — No Rotation — MITRE T1552")
    secret = sm.create_secret(
        Name=f"{PREFIX}/db-password-{TIMESTAMP}",
        Description="CSPM Lab: Secret without rotation enabled",
        SecretString=json.dumps({
            "username": "admin",
            "password": "Lab@NoRotation123!",
            "host": "lab-db.example.com",
        }),
        Tags=[
            {"Key": "Name", "Value": f"{PREFIX}-no-rotation-secret"},
            {"Key": "Purpose", "Value": "CSPM Lab Testing"},
        ],
    )
    # Intentionally do NOT enable rotation
    print_ok(f"Created secret WITHOUT rotation: {secret['Name']}")
    print_warn("Rotation is disabled (default) — CSPM should flag this as MEDIUM")
    return secret["ARN"]


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 10 — S3 Bucket with no encryption  (Expected: MEDIUM)
# ═══════════════════════════════════════════════════════════════════════════════
def create_unencrypted_s3(s3, region):
    print_step(10, "S3 Bucket Without Encryption — CIS 2.1.2 / MITRE T1005")
    bucket_name = f"{PREFIX}-no-encryption-{TIMESTAMP}"

    kwargs = {"Bucket": bucket_name}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)

    # Block public access (this bucket is private but unencrypted)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    # Intentionally skip: s3.put_bucket_encryption(...)

    print_ok(f"Created unencrypted S3 bucket: {bucket_name}")
    print_warn("No SSE configured — CSPM should flag CIS 2.1.2 as MEDIUM")
    return bucket_name


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER — Get or create VPC
# ═══════════════════════════════════════════════════════════════════════════════
def get_default_vpc(ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    if vpcs["Vpcs"]:
        vpc_id = vpcs["Vpcs"][0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        az = subnets["Subnets"][0]["AvailabilityZone"]
        print_ok(f"Using default VPC: {vpc_id} | AZ: {az}")
        return vpc_id, az
    raise RuntimeError("No default VPC found. Create one in AWS Console first.")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="CSPM Lab Setup — creates 10 misconfigured AWS resources")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be created, don't create")
    args = parser.parse_args()

    print_header(f"CSPM Lab Setup — Region: {args.region}")
    if args.dry_run:
        print("  DRY RUN MODE — nothing will be created")
        print("\n  Would create:")
        print("  1. Public S3 bucket (ACL public-read, no block public access)")
        print("  2. Security group: SSH (22) open to 0.0.0.0/0")
        print("  3. Security group: RDP (3389) open to 0.0.0.0/0 + ::/0")
        print("  4. IAM user with AdministratorAccess directly attached")
        print("  5. Check root MFA status")
        print("  6. CloudTrail trail with logging stopped")
        print("  7. Unencrypted EBS volume (1 GB gp3)")
        print("  8. Public RDS MySQL instance (db.t3.micro, no encryption)")
        print("  9. Secrets Manager secret with no rotation")
        print("  10. S3 bucket with no server-side encryption")
        return

    # Initialize AWS clients
    session = boto3.Session(region_name=args.region)
    s3  = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")
    ct  = session.client("cloudtrail")
    rds = session.client("rds")
    sm  = session.client("secretsmanager")

    # Verify credentials
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    print_ok(f"AWS Identity: {identity['Arn']}")
    print_ok(f"Account: {identity['Account']}")

    vpc_id, az = get_default_vpc(ec2)

    created = {}

    try:
        created["s3_public"]        = create_public_s3_bucket(s3, args.region)
        created["sg_ssh"]           = create_open_ssh_sg(ec2, vpc_id)
        created["sg_rdp"]           = create_open_rdp_sg(ec2, vpc_id)
        created["iam_user"]         = create_admin_iam_user(iam)
        check_root_mfa(iam)
        created["cloudtrail"], created["ct_bucket"] = disable_cloudtrail(ct, args.region)
        created["ebs_vol"]          = create_unencrypted_ebs(ec2, az)
        created["rds_db"]           = create_public_rds(rds, created["sg_ssh"], args.region)
        created["secret"]           = create_secret_no_rotation(sm)
        created["s3_no_enc"]        = create_unencrypted_s3(s3, args.region)

    except Exception as e:
        print(f"\n❌ Error during setup: {e}")
        import traceback; traceback.print_exc()

    # Save resource manifest for cleanup script
    import json as _json
    manifest = {
        "timestamp": TIMESTAMP,
        "region": args.region,
        "account": identity["Account"],
        "resources": created,
    }
    with open("lab_manifest.json", "w") as f:
        _json.dump(manifest, f, indent=2, default=str)

    print_header("Lab Setup Complete!")
    print(f"\n  Resources saved to: lab_manifest.json")
    print(f"\n  Expected CSPM findings:")
    print(f"  ├─ CRITICAL : 3  (RDP open, IAM admin user, CloudTrail stopped)")
    print(f"  ├─ HIGH     : 4  (Public S3, SSH open, Public RDS, No MFA on root)")
    print(f"  └─ MEDIUM   : 5  (Unencrypted EBS, No S3 encryption, No rotation,")
    print(f"                     No RDS backup, No deletion protection)")
    print(f"\n  Now trigger a scan in your CSPM platform and verify all findings appear.")
    print(f"\n  ⚠️  Run python cleanup.py when done to delete all resources.")


if __name__ == "__main__":
    main()
