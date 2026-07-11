"""
cleanup.py — Deletes all CSPM lab resources created by setup_lab.py
Reads lab_manifest.json to know exactly what to delete.

Usage:
    python cleanup.py
    python cleanup.py --manifest lab_manifest.json
"""

import boto3
import json
import argparse
import time


def load_manifest(path="lab_manifest.json"):
    with open(path) as f:
        return json.load(f)


def delete_s3_bucket(s3, bucket_name):
    if not bucket_name:
        return
    try:
        # Delete all objects first
        paginator = s3.get_paginator("list_object_versions")
        try:
            for page in paginator.paginate(Bucket=bucket_name):
                objects = []
                for v in page.get("Versions", []):
                    objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
                for m in page.get("DeleteMarkers", []):
                    objects.append({"Key": m["Key"], "VersionId": m["VersionId"]})
                if objects:
                    s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
        except Exception:
            # Non-versioned bucket
            objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            if objects:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objects]},
                )
        s3.delete_bucket(Bucket=bucket_name)
        print(f"  ✅  Deleted S3 bucket: {bucket_name}")
    except s3.exceptions.NoSuchBucket:
        print(f"  ⚠️   S3 bucket already deleted: {bucket_name}")
    except Exception as e:
        print(f"  ❌  S3 {bucket_name}: {e}")


def delete_security_group(ec2, sg_id):
    if not sg_id:
        return
    try:
        ec2.delete_security_group(GroupId=sg_id)
        print(f"  ✅  Deleted security group: {sg_id}")
    except ec2.exceptions.ClientError as e:
        print(f"  ⚠️   SG {sg_id}: {e.response['Error']['Message']}")


def delete_iam_user(iam, user_name):
    if not user_name:
        return
    try:
        # Detach all policies
        policies = iam.list_attached_user_policies(UserName=user_name)
        for p in policies["AttachedPolicies"]:
            iam.detach_user_policy(UserName=user_name, PolicyArn=p["PolicyArn"])
        # Delete login profile
        try:
            iam.delete_login_profile(UserName=user_name)
        except Exception:
            pass
        # Delete access keys
        keys = iam.list_access_keys(UserName=user_name)
        for k in keys["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        iam.delete_user(UserName=user_name)
        print(f"  ✅  Deleted IAM user: {user_name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"  ⚠️   IAM user already deleted: {user_name}")
    except Exception as e:
        print(f"  ❌  IAM user {user_name}: {e}")


def delete_cloudtrail(ct, trail_arn):
    if not trail_arn:
        return
    try:
        ct.delete_trail(Name=trail_arn)
        print(f"  ✅  Deleted CloudTrail: {trail_arn}")
    except Exception as e:
        print(f"  ⚠️   CloudTrail: {e}")


def delete_ebs_volume(ec2, vol_id):
    if not vol_id:
        return
    try:
        ec2.delete_volume(VolumeId=vol_id)
        print(f"  ✅  Deleted EBS volume: {vol_id}")
    except Exception as e:
        print(f"  ⚠️   EBS {vol_id}: {e}")


def delete_rds_instance(rds, db_id):
    if not db_id:
        return
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=db_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
        print(f"  ✅  Deleting RDS: {db_id} (takes ~5 min)")
    except rds.exceptions.DBInstanceNotFoundFault:
        print(f"  ⚠️   RDS already deleted: {db_id}")
    except Exception as e:
        print(f"  ❌  RDS {db_id}: {e}")


def delete_secret(sm, secret_arn):
    if not secret_arn:
        return
    try:
        sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        print(f"  ✅  Deleted secret: {secret_arn}")
    except Exception as e:
        print(f"  ⚠️   Secret: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="lab_manifest.json")
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest)
    except FileNotFoundError:
        print("❌  lab_manifest.json not found. Run setup_lab.py first.")
        return

    region   = manifest["region"]
    resources = manifest["resources"]

    print(f"\n{'='*55}")
    print(f"  CSPM Lab Cleanup — Region: {region}")
    print(f"  Account: {manifest['account']}")
    print(f"{'='*55}\n")

    session = boto3.Session(region_name=region)
    s3  = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")
    ct  = session.client("cloudtrail")
    rds = session.client("rds")
    sm  = session.client("secretsmanager")

    # Delete in safe order (dependencies first)
    delete_cloudtrail(ct, resources.get("cloudtrail"))
    delete_s3_bucket(s3, resources.get("s3_public"))
    delete_s3_bucket(s3, resources.get("s3_no_enc"))
    delete_s3_bucket(s3, resources.get("ct_bucket"))
    delete_iam_user(iam, resources.get("iam_user"))
    delete_rds_instance(rds, resources.get("rds_db"))

    # Wait for RDS to start deleting before removing its SG
    print("\n  Waiting 30s for RDS deletion to start...")
    time.sleep(30)

    delete_security_group(ec2, resources.get("sg_ssh"))
    delete_security_group(ec2, resources.get("sg_rdp"))
    delete_ebs_volume(ec2, resources.get("ebs_vol"))
    delete_secret(sm, resources.get("secret"))

    print(f"\n✅  Cleanup complete! All lab resources deleted.")
    print(f"  Note: RDS instance deletion continues in background (~5 min).")


if __name__ == "__main__":
    main()
