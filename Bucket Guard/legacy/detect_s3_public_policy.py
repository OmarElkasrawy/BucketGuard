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

    print(f"Bucket {bucket_name} retrieved successfully, has a policy: {policy}")
    print(json.dumps(policy_dict, indent=4, sort_keys=True))

    is_public = False

    for statement in policy_dict.get('Statement', []):
        if statement.get("Principal") == "*":
            is_public = True
            print(f"\nWARNING: Bucket '{bucket_name}' is PUBLICLY accessible!\n")
            break

    if not is_public:
        print(f"\nBucket '{bucket_name}' is PRIVATE\n")

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
    else:
        print(f"\n'Block All Public Access' is ENABLED for '{bucket_name}'\n")

except s3.exceptions.ClientError as e:
    if 'NoSuchPublicAccessBlockConfiguration' in str(e):
        print(f"Bucket {bucket_name} retrieved successfully, but has no public access block")
    else:
        print(f"Error: {e}")