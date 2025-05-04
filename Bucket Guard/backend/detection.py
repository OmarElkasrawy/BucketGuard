import json
import boto3
from db_handler import get_misconfigurations

s3 = boto3.client('s3')

def detect_misconfigurations(bucket_name):
    """Detects misconfigs dynamically from db"""
    detected_issues = []

    misconfigurations = get_misconfigurations()

    for issue, remediation_code, cis_ref in misconfigurations:
        if "Public access is enabled" in issue:
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_dict = json.loads(policy['Policy'])
                is_public = any(
                    statement.get("Principal") == "*" or "*" in statement.get("Principal", {}).values()
                    for statement in policy_dict.get("Statement", [])
                )
                if is_public:
                    detected_issues.append({
                        'issue': issue,
                        'remediation_code': remediation_code,
                        'cis_reference': cis_ref
                    })
            except s3.exceptions.ClientError as e:
                if 'NoSuchBucketPolicy' in str(e):
                    pass # no bucket policy = good
                else:
                    print(f"\n❌ Error checking bucket policy: {e}")

        elif "Versioning is disabled" in issue:
            try:
                response = s3.get_bucket_versioning(Bucket=bucket_name)
                status = response.get('Status', 'Disabled')
                if status != 'Enabled':
                    detected_issues.append({
                        'issue': issue,
                        'remediation_code': remediation_code,
                        'cis_reference': cis_ref
                    })
            except s3.exceptions.ClientError as e:
                print(f"\n❌ Error checking bucket versioning: {e}")
        
        elif "Block Public Access is disabled" in issue:
            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                config = response.get('PublicAccessBlockConfiguration')
                if not all(config.values()):
                    detected_issues.append({
                        'issue': issue,
                        'remediation_code': remediation_code,
                        'cis_reference': cis_ref
                    })
            except s3.exceptions.ClientError as e:
                if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                    detected_issues.append({
                        'issue': issue,
                        'remediation_code': remediation_code,
                        'cis_reference': cis_ref
                    })
                else:
                    print(f"\n❌ Error checking bucket public access block: {e}")
    return detected_issues