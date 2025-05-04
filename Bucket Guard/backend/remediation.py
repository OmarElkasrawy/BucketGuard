import boto3
from db_handler import get_misconfigurations


s3 = boto3.client('s3')

def remediate_issue(bucket_name, issue):
    """Remediate an issue dynamically based on db logic"""
    # Get remediation code from database
    misconfigurations = get_misconfigurations()
    remediation_code = None
    
    # Find the matching issue and its remediation code
    for db_issue, db_remediation, _ in misconfigurations:
        if db_issue == issue:
            remediation_code = db_remediation
            break
    
    if not remediation_code:
        return "No remediation available for this issue"
    
    # Call the appropriate remediation function
    if remediation_code == "remediate_public_access":
        return remediate_public_access(bucket_name)
    elif remediation_code == "remediate_missing_versioning":
        return remediate_missing_versioning(bucket_name)
    elif remediation_code == "remediate_block_public_access":
        return remediate_block_public_access(bucket_name)
    else:
        return "Unknown remediation code"
    
def remediate_public_access(bucket_name):
    """Removes public bucket policy"""

    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
        return f"✅ Public access removed for {bucket_name}."
    except s3.exceptions.ClientError as e:
        return f"❌ Error removing public access: {e}"
    
def remediate_missing_versioning(bucket_name):
    """Enables versioning"""

    try:
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        return f"✅ Versioning enabled for {bucket_name}."
    except s3.exceptions.ClientError as e:
        return f"❌ Error enabling versioning: {e}"
    
def remediate_block_public_access(bucket_name):
    """Enables block public access option"""

    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        return f"✅ Block public access enabled for {bucket_name}."
    except s3.exceptions.ClientError as e:
        return f"❌ Error enabling block public access: {e}"