import boto3
import json
import pyfiglet

ascii_banner = pyfiglet.figlet_format("Bucket Guard")
print("=" * 40)
print(ascii_banner)
print("=" * 40)

s3 = boto3.client('s3')

bucket_name = 'misconfigured-dummy1-test'

try:
    policy = s3.get_bucket_policy(Bucket=bucket_name)
    policy_dict = json.loads(policy['Policy'])

    print(f"Bucket {bucket_name} retrieved successfully")
    print(json.dumps(policy_dict, indent=4, sort_keys=True))

    modified_statements = []
    is_public = False

    for statement in policy_dict.get("Statement", []):
        if statement.get("Principal") == "*":
            is_public = True
            print(f"\nWARNING: Bucket '{bucket_name}' is PUBLICLY accessible!\n")
        else:
            modified_statements.append(statement)

    if is_public:
        if modified_statements: # update policy if still valid statements
            fixed_policy = {
                "Version": policy_dict.get("Version"),
                "Statement": modified_statements
            }
            s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(fixed_policy))
            print(f"Public access removed! Updated policy applied to '{bucket_name}'")
        else: # if all statements were public then delete the policy entirely
            s3.delete_bucket_policy(Bucket=bucket_name)
            print(f"Public access removed! Bucket '{bucket_name}'")

    else:
        print(f"No public access found in bucket '{bucket_name}'. No changes needed.")

except s3.exceptions.ClientError as e:
    if 'NoSuchBucketPolicy' in str(e):
        print(f"Bucket {bucket_name} retrieved successfully, but has no policy")
    else:
        print(f"Error: {e}")

try:
    response = s3.get_public_access_block(Bucket=bucket_name)
    config = response["PublicAccessBlockConfiguration"]

    if not all(config.values()):
        print(f"\nWARNING: 'Block All Public Access' is DISABLED for '{bucket_name}'")

        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"Block All Public Access applied to '{bucket_name}'")
    else:
        print(f"\n'Block All Public Access' is ENABLED for '{bucket_name}'")

except s3.exceptions.ClientError as e:
    if 'NoSuchPublicAccessBlockConfiguration' in str(e):
        print(f"Bucket {bucket_name} retrieved successfully, but has no public access block")
    else:
        print(f"Error: {e}")