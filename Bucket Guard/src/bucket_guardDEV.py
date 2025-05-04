import boto3
import json
import sqlite3
import pyfiglet

# Initialize AWS S3 client
s3 = boto3.client('s3')

# Print ASCII banner
ascii_banner = pyfiglet.figlet_format("Bucket Guard")
print("=" * 40)
print(ascii_banner)
print("=" * 40)
print("\n🛡️ Protecting Your Cloud, One Bucket at a Time. 🔒\n")


def list_buckets():
    """Lists all available S3 buckets and lets the user choose one."""
    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        if not buckets:
            print("\n❌ No S3 buckets found in your AWS account.")
            return None

        print("\n📂 Available S3 Buckets:\n")
        for idx, bucket in enumerate(buckets, start=1):
            print(f"  {idx}. {bucket['Name']}")

        while True:
            choice = input("\n🛠 Select a bucket by number: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(buckets):
                return buckets[int(choice) - 1]["Name"]
            else:
                print("❌ Invalid choice. Please enter a valid number.")

    except s3.exceptions.ClientError as e:
        print(f"\n❌ Error listing buckets: {e}")
        return None
    
def prompt_remediation(remediation_function, bucket_name):
    """Prompts user to remediate the detected issue and returns True if remediation was applied."""
    while True:
        print("\n⚠️ Would you like to remediate this issue?")
        print("1. Yes (Fix it now)")
        print("2. No (Return to main menu)")
        print("3. Exit")

        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            remediation_function(bucket_name)
            return True  # ✅ Return True when remediation is applied
        elif choice == "2":
            return False  # ✅ Return False when the user refuses
        elif choice == "3":
            print("\n👋 Exiting... Stay secure!\n")
            exit()
        else:
            print("\n❌ Invalid option. Please enter 1, 2, or 3.")


def detect_public_access(bucket_name):
    """Detect if S3 bucket is publicly accessible (CIS AWS Foundations Benchmark S3.1 & S3.8)."""
    no_policy = False  # Track if the bucket has no policy

    try:
        # Attempt to get bucket policy
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        policy_json = policy['Policy']
        policy_dict = json.loads(policy_json)

        # Check if the policy allows public access (CIS S3.8)
        is_public = False
        for statement in policy_dict.get('Statement', []):
            principal = statement.get("Principal", {})

            # Ensure Principal is handled correctly (dict or wildcard "*")
            if principal == "*" or "*" in principal.values():
                is_public = True
                print(f"\n⚠️ WARNING: Bucket '{bucket_name}' has a PUBLIC policy! ❌ (CIS AWS Foundations Benchmark S3.8 - Non-Compliant)\n")
                break

        if not is_public:
            print(f"\n✅ Bucket '{bucket_name}' does not have a public policy. ✅ (CIS AWS Foundations Benchmark S3.8 - Compliant)\n")

    except s3.exceptions.ClientError as e:
        if 'NoSuchBucketPolicy' in str(e):
            no_policy = True  # Mark that no policy exists
        else:
            print(f"\n❌ Error: {e}")

    # Check Public Access Block Configuration (CIS S3.1)
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        if all(config.values()):  # All settings are True (safe)
            print(f"\n✅ 'Block All Public Access' is ENABLED for '{bucket_name}'. ✅ (CIS AWS Foundations Benchmark S3.1 - Compliant)\n")
            return  # Exit since bucket is safe

        # If "Block All Public Access" is disabled, warn and offer remediation
        print(f"\n⚠️ WARNING: 'Block All Public Access' is DISABLED for '{bucket_name}'! ❌ (CIS AWS Foundations Benchmark S3.1 - Non-Compliant)\n")
        remediation_successful = prompt_remediation(remediate_block_public_access, bucket_name)

        # ✅ **Re-fetch latest AWS settings after remediation**
        if remediation_successful:
            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                config = response["PublicAccessBlockConfiguration"]

                if all(config.values()):  
                    print(f"\n✅ 'Block All Public Access' is now ENABLED for '{bucket_name}' ✅ (CIS AWS Foundations Benchmark S3.1 - Compliant).\n")
                    return  # ✅ Exit cleanly, avoiding false warnings
            except s3.exceptions.ClientError as e:
                print(f"\n❌ Error retrieving updated settings: {e}")

        # Final check to warn if both policy is missing and block is still disabled
        if no_policy and not all(config.values()):
            print(f"\n⚠️ WARNING: No bucket policy found, and 'Block All Public Access' is STILL DISABLED! This bucket might be vulnerable.\n")

    except s3.exceptions.ClientError as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            print(f"\n⚠️ WARNING: No 'Block All Public Access' configuration found for '{bucket_name}'!\n")
            prompt_remediation(remediate_block_public_access, bucket_name)
        else:
            print(f"\n❌ Error: {e}")



def detect_missing_versioning(bucket_name):
    """Detect if S3 bucket has versioning disabled (CIS AWS Foundations Benchmark S3.14)."""
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')

        if status != 'Enabled':
            print(f"\n⚠️ WARNING: Versioning is DISABLED for '{bucket_name}' ❌ (CIS AWS Foundations Benchmark S3.14 - Non-Compliant)\n")
            prompt_remediation(remediate_missing_versioning, bucket_name)
        else:
            print(f"\n✅ Versioning is ENABLED for '{bucket_name}' ✅ (CIS AWS Foundations Benchmark S3.14 - Compliant)\n")
    
    except s3.exceptions.ClientError as e:
        print(f"\n❌ Error checking versioning: {e}")

def detect_encryption(bucket_name):
    """Detects and displays whether AES-256 encryption (SSE-S3) is applied to the S3 bucket."""
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

        if rules:
            encryption_type = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

            # Only show if encryption is AES-256 (SSE-S3)
            if encryption_type == "AES256":
                print(f"\n✅ Encryption is ENABLED for '{bucket_name}' using: AES-256 (SSE-S3)\n")
            else:
                print(f"\n⚠️ WARNING: Bucket '{bucket_name}' has an unexpected encryption type: {encryption_type}\n")

        else:
            print(f"\n⚠️ WARNING: No encryption settings found for '{bucket_name}'!\n")

    except s3.exceptions.ClientError as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            print(f"\n⚠️ WARNING: No encryption settings found for '{bucket_name}'!\n")
        else:
            print(f"\n❌ Error: {e}")


def remediate_public_access(bucket_name):
    """Remediates public access misconfigurations by deleting the bucket policy and enabling 'Block All Public Access' only if necessary."""
    try:
        print("\n🔧 Checking public access misconfigurations...\n")

        # 1️⃣ Check if the bucket already has "Block All Public Access" enabled
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response["PublicAccessBlockConfiguration"]

            if all(config.values()):  # Already fully enabled
                block_public_access_needed = False
            else:
                block_public_access_needed = True
        except s3.exceptions.ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                block_public_access_needed = True  # No configuration found, must enable
            else:
                print(f"\n❌ Error checking 'Block All Public Access': {e}")
                return

        # 2️⃣ Check if the bucket has a public policy
        try:
            s3.get_bucket_policy(Bucket=bucket_name)  # If policy exists, deletion is needed
            policy_exists = True
        except s3.exceptions.ClientError as e:
            if 'NoSuchBucketPolicy' in str(e):
                policy_exists = False  # No policy found, no need to delete
            else:
                print(f"\n❌ Error checking bucket policy: {e}")
                return

        # 3️⃣ Delete bucket policy only if it exists
        if policy_exists:
            try:
                s3.delete_bucket_policy(Bucket=bucket_name)
                print(f"✅ Public access removed! Policy deleted for '{bucket_name}' ✅ (CIS AWS Foundations Benchmark S3.8 - Compliant).\n")
            except s3.exceptions.ClientError as e:
                print(f"\n❌ Error deleting public access policy: {e}")

        else:
            print(f"ℹ️ No bucket policy found for '{bucket_name}', skipping policy deletion.\n")

        # 4️⃣ Enable "Block All Public Access" only if needed
        if block_public_access_needed:
            try:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    }
                )
                print(f"✅ 'Block All Public Access' is now ENABLED for '{bucket_name}' ✅ (CIS AWS Foundations Benchmark S3.1 - Compliant).\n")
            except s3.exceptions.ClientError as e:
                print(f"\n❌ Error enabling 'Block All Public Access': {e}")

        else:
            print(f"ℹ️ 'Block All Public Access' was already enabled for '{bucket_name}', no changes made.\n")

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")



def remediate_missing_versioning(bucket_name):
    """Enables versioning on the bucket if it is disabled."""
    try:
        print("\n🔧 Checking versioning status...\n")

        # 1️⃣ Check if versioning is already enabled
        try:
            response = s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get('Status', 'Disabled')

            if status == 'Enabled':
                print(f"ℹ️ Versioning is already enabled for '{bucket_name}', no changes made.\n")
                return  # ✅ Exit early, no need to make changes

        except s3.exceptions.ClientError as e:
            print(f"\n❌ Error checking versioning: {e}")
            return

        # 2️⃣ If versioning is disabled, enable it
        try:
            s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            print(f"✅ Versioning enabled for '{bucket_name}'. ✅ (CIS AWS Foundations Benchmark S3.14 - Compliant)\n")
        except s3.exceptions.ClientError as e:
            print(f"\n❌ Error enabling versioning: {e}")

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


def remediate_block_public_access(bucket_name):
    """Enables 'Block All Public Access' for the bucket."""
    try:
        print("\n🔧 Enabling 'Block All Public Access'...\n")
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        print(f"✅ 'Block All Public Access' is now ENABLED for '{bucket_name}' ✅ (CIS AWS Foundations Benchmark S3.1 - Compliant)!\n")
        return True  # Indicate that remediation was successful
    except s3.exceptions.ClientError as e:
        print(f"\n❌ Error enabling 'Block All Public Access': {e}")
        return False  # Indicate that remediation failed

def remediate_missing_encryption(bucket_name):
    print("test")


def detect_misconfigurations(bucket_name):
    """Detects misconfigurations dynamically from the database"""
    detected_issues = [] # Store detected misconfigs

    # conn to db
    conn = sqlite3.connect(r"D:\TKH COV\awsCLI\BucketGuard\Bucket Guard\DB\bucketguard.db")
    cursor = conn.cursor()

    # Fetch all misconfigs from db
    cursor.execute("SELECT issue, remediation_code, cis_reference FROM misconfigurations")
    misconfigurations = cursor.fetchall()
    conn.close()

    print(f"\n🔍 Scanning bucket: {bucket_name}...\n")

    # Check each misconfig dynamically
    for issue, remediation_code, cis_ref in misconfigurations:
        if "Public access is enabled" in issue:
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_dict = json.loads(policy['Policy'])
                is_public = any(
                    statement.get("Principal") == "*" or "*" in statement.get("Principal", {}).values()
                    for statement in policy_dict.get('Statement', [])
                )
                if is_public:
                    detected_issues.append((issue, remediation_code, cis_ref))
            except s3.exceptions.ClientError as e:
                if 'NoSuchBucketPolicy' in str(e):
                    print(f"\n✅ No bucket policy found for '{bucket_name}'.\n")
                else:
                    print(f"\n❌ Error checking bucket policy: {e}")

        elif "Versioning is disabled" in issue:
            try:
                response = s3.get_bucket_versioning(Bucket=bucket_name)
                status = response.get('Status', 'Disabled')
                if status != 'Enabled':
                    detected_issues.append((issue, remediation_code, cis_ref))
            except s3.exceptions.ClientError as e:
                print(f"\nError checking versioning: {e}")
        
        elif "Block Public Access is disabled" in issue:
            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                config = response["PublicAccessBlockConfiguration"]
                if not all(config.values()):
                    detected_issues.append((issue, remediation_code, cis_ref))
            except s3.exceptions.ClientError as e:
                if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                    detected_issues.append((issue, remediation_code, cis_ref))
                else:
                    print(f"\nError checking 'Block All Public Access': {e}")

    # Display Scan Results
    print("\n==== Scan Results ====")
    if detected_issues:
        for issue, remediation_code, cis_ref in detected_issues:
            print(f"⚠️ {issue} ({cis_ref} - Non-Compliant)")

        print("\nWould you like to remediate all issues now?")
        print("1. Yes (Fix all issues)")
        print("2. No (Return to main menu)")
        print("3. Exit")

        choice = input("Select an option (1-3): ").strip()
        
        if choice == "1":
            for issue, remediation_code, cis_ref in detected_issues:
                remediation_function = globals().get(remediation_code)
                if remediation_function:
                    print(f"\n🔧 Applying remediation: {remediation_code} for {issue}...\n")
                    remediation_function(bucket_name)
                else:
                    print(f"\n❌ Error: Remediation function '{remediation_code}' not found.")
            print("\n✅ All detected issues have been remediated!\n")

        elif choice == "2":
            return
        
        elif choice == "3":
            print("\n👋 Exiting... Stay secure!\n")
            exit()
        else:
            print("\n❌ Invalid option. Returning to main menu.")
    else:
        print("✅ No misconfigurations detected. Your bucket is secure and compliant with the following ...")
        print("CIS AWS Foundations Benchmark:")
        print(" ✅ - S3.1: Block Public Access Settings Enabled")
        print(" ✅ - S3.8: Public Access Policy Removed")
        print(" ✅ - S3.14: Versioning Enabled")

            
def detection_menu(bucket_name):
    """Handles detection submenu"""
    detect_misconfigurations(bucket_name)

def remediation_menu(bucket_name):
    """Handles remediation submenu"""
    while True:
        print("\n==== Remediation Menu ====")
        print("1. Fix Public Access")
        print("2. Fix Missing Versioning")
        print("3. Back to Main Menu")

        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            remediate_public_access(bucket_name)
        elif choice == "2":
            remediate_missing_versioning(bucket_name)
        elif choice == "3":
            return
        else:
            print("\n❌ Invalid option. Please try again.")

def main():
    """Main menu function."""

    bucket_name = list_buckets()
    if not bucket_name:
        print("\n❌ Exiting ... No bucket selected.")
        return
    
    while True:
        print("\n=====================================")
        print(f"🔍 Scanning: {bucket_name}\n")
        print("1. Detection Menu 🔍")
        print("2. Remediation Menu 🔧")
        print("3. Choose a Different Bucket 📂")
        print("4. Exit 🚪")
        print("=====================================")

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            detection_menu(bucket_name)
        elif choice == "2":
            remediation_menu(bucket_name)
        elif choice == "3":
            bucket_name = list_buckets()
            if not bucket_name:
                print("\n❌ Exiting... No bucket selected.")
                return
        elif choice == "4":
            print("\n👋 Exiting... Stay secure!\n")
            break
        else:
            print("\n❌ Invalid option. Please try again.")

if __name__ == "__main__":
    main()
