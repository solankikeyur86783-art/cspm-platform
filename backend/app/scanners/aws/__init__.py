from app.scanners.aws.iam import AWSIAMScanner
from app.scanners.aws.s3 import AWSS3Scanner
from app.scanners.aws.ec2 import AWSEC2Scanner
from app.scanners.aws.rds import AWSRDSScanner
from app.scanners.aws.vpc import AWSVPCScanner
from app.scanners.aws.cloudtrail import AWSCloudTrailScanner
from app.scanners.aws.secrets_manager import AWSSecretsManagerScanner
from app.scanners.aws.lambda_scanner import AWSLambdaScanner

AWS_SCANNERS = [
    AWSIAMScanner,
    AWSS3Scanner,
    AWSEC2Scanner,
    AWSRDSScanner,
    AWSVPCScanner,
    AWSCloudTrailScanner,
    AWSSecretsManagerScanner,
    AWSLambdaScanner,        # Step 16 — Lambda overly permissive role
]

__all__ = [
    "AWSIAMScanner", "AWSS3Scanner", "AWSEC2Scanner",
    "AWSRDSScanner", "AWSVPCScanner", "AWSCloudTrailScanner",
    "AWSSecretsManagerScanner", "AWSLambdaScanner",
    "AWS_SCANNERS",
]
