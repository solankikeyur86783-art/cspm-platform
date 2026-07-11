"""
create_lambda_zip.py — Creates the lambda_function.zip needed by Terraform.
Run this BEFORE terraform apply.

Usage:  python create_lambda_zip.py
"""
import zipfile, os

# Simple Lambda handler
code = '''
def handler(event, context):
    """CSPM Lab Lambda — intentionally has admin role attached."""
    return {
        "statusCode": 200,
        "body": "CSPM Lab Lambda running"
    }
'''

zip_path = os.path.join(os.path.dirname(__file__), "lambda_function.zip")
with zipfile.ZipFile(zip_path, "w") as zf:
    zf.writestr("index.py", code)

print(f"✅  Created: {zip_path}")
print("    Now run: terraform apply")
