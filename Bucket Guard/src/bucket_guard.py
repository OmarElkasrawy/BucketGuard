import os
import boto3
import json
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import re
import pyfiglet
import datetime

# Initialie AWS S3 client
s3 = boto3.client('s3')

# Print ASCII banner
ascii_banner = pyfiglet.figlet_format("Bucket Guard")
print("=" * 40)
print(ascii_banner)
print("=" * 40)
print("\n🛡️ Protecting Your Cloud, One Bucket at a Time. 🔒\n")

def remove_emojis(text):
    """Removes emojis from a string"""
    return re.sub(r'[^\w\s,:/-]', '', text)  # Keeps words, spaces, colons, commas, and slashes

def generate_plain_text_report(bucket_name, findings):
    """Generates a security report in plain text format inside 'generated_reports/txt/' folder."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")  # Format: YYYY-MM-DD_HH-MM-SS

    # ✅ Define folder for TXT reports
    report_folder = os.path.join("generated_reports", "txt")
    os.makedirs(report_folder, exist_ok=True)

    txt_filename = os.path.join(report_folder, f"BucketGuard_Report_{bucket_name}_{timestamp}.txt")

    with open(txt_filename, "w", encoding="utf-8") as report:
        report.write(f"BucketGuard Security Report\n")
        report.write(f"===========================\n")
        report.write(f"Bucket Name: {bucket_name}\n")
        report.write(f"Date of Report: {timestamp}\n\n")
        report.write(f"🔍 Security Findings:\n")

        for key, value in findings.items():
            if key != "recommendations":
                report.write(f"- {value}\n")

        report.write("\n⚠️ Recommended Fixes:\n")
        if not findings.get("recommendations"):
            report.write("- None\n")
        else:
            for key, value in findings.get("recommendations", {}).items():
                report.write(f"- {value}\n")

    print(f"\n✅ Plain text report saved in: {txt_filename}")

    # ✅ Move the export prompt **before returning**
    while True:
        print("\nWould you like to export the report to another format?")
        print("1. Export as JSON")
        print("2. Export as CSV")
        print("3. Export as PDF")
        print("4. No, return to main menu")

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            export_as_json(bucket_name, findings, timestamp)
        elif choice == "2":
            export_as_csv(bucket_name, findings, timestamp)
        elif choice == "3":
            export_as_pdf(bucket_name, findings, timestamp)
        elif choice == "4":
            print("\nReturning to main menu...\n")
            break  # ✅ Exit the loop instead of returning early
        else:
            print("\n❌ Invalid option. Please try again.")

    return txt_filename  # ✅ Now this executes after user input


def export_as_json(bucket_name, findings, timestamp):
    """Exports the security report as a JSON file inside 'generated_reports/json/' folder."""
    # ✅ Define folder for JSON reports
    report_folder = os.path.join("generated_reports", "json")
    os.makedirs(report_folder, exist_ok=True)

    json_filename = os.path.join(report_folder, f"BucketGuard_Report_{bucket_name}_{timestamp}.json")

    try:
        sanitized_findings = {k: remove_emojis(v) for k, v in findings.items() if k != "recommendations"}
        sanitized_recommendations = {k: remove_emojis(v) for k, v in findings.get("recommendations", {}).items()}

        with open(json_filename, "w", encoding="utf-8") as json_file:
            json.dump({
                "Bucket Name": bucket_name,
                "Date of Report": timestamp,
                "Security Findings": sanitized_findings,
                "Recommended Fixes": sanitized_recommendations if sanitized_recommendations else "None"
            }, json_file, indent=4)

        print(f"\n✅ JSON report saved in: {json_filename}")

    except Exception as e:
        print(f"\n❌ Error exporting JSON report: {e}")

def export_as_csv(bucket_name, findings, timestamp):
    """Exports the security report as a CSV file inside 'generated_reports/csv/' folder, removing emojis."""
    # ✅ Define folder for CSV reports
    report_folder = os.path.join("generated_reports", "csv")
    os.makedirs(report_folder, exist_ok=True)

    csv_filename = os.path.join(report_folder, f"BucketGuard_Report_{bucket_name}_{timestamp}.csv")

    try:
        with open(csv_filename, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)

            # ✅ Write CSV Header
            writer.writerow(["Category", "Details"])

            # ✅ Write Security Findings
            writer.writerow(["Bucket Name", bucket_name])
            writer.writerow(["Date of Report", timestamp])
            writer.writerow([])
            writer.writerow(["Security Findings"])
            for key, value in findings.items():
                if key != "recommendations":
                    writer.writerow([key, remove_emojis(value)])

            # ✅ Write Recommended Fixes
            writer.writerow([])
            writer.writerow(["Recommended Fixes"])
            if not findings.get("recommendations"):
                writer.writerow(["None", ""])
            else:
                for key, value in findings.get("recommendations", {}).items():
                    writer.writerow([key, remove_emojis(value)])

        print(f"\n✅ CSV report saved in: {csv_filename}")

    except Exception as e:
        print(f"\n❌ Error exporting CSV report: {e}")
        
def export_as_pdf(bucket_name, findings, timestamp):
    """Exports the security report as a PDF file inside 'generated_reports/pdf/' folder, keeping emojis and wrapping text."""
    # ✅ Define folder for PDF reports
    report_folder = os.path.join("generated_reports", "pdf")
    os.makedirs(report_folder, exist_ok=True)

    pdf_filename = os.path.join(report_folder, f"BucketGuard_Report_{bucket_name}_{timestamp}.pdf")

    try:
        c = canvas.Canvas(pdf_filename, pagesize=letter)
        width, height = letter

        # ✅ Report Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "BucketGuard Security Report")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 70, "=" * 50)

        # ✅ Bucket & Date Info
        c.drawString(50, height - 90, f"Bucket Name: {bucket_name}")
        c.drawString(50, height - 110, f"Date of Report: {timestamp}")

        # ✅ Security Findings
        y_position = height - 140
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_position, "🔍 Security Findings:")
        c.setFont("Helvetica", 11)

        y_position -= 20
        for key, value in findings.items():
            if key != "recommendations":
                wrapped_text = simpleSplit(value, "Helvetica", 11, width - 100)  # ✅ Wrap long text
                for line in wrapped_text:
                    c.drawString(50, y_position, f"- {line}")
                    y_position -= 20  # Move down for each wrapped line

        # ✅ Recommended Fixes
        y_position -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_position, "⚠️ Recommended Fixes:")
        c.setFont("Helvetica", 11)

        y_position -= 20
        if not findings.get("recommendations"):
            c.drawString(50, y_position, "- None")
        else:
            for key, value in findings.get("recommendations", {}).items():
                wrapped_text = simpleSplit(value, "Helvetica", 11, width - 100)  # ✅ Wrap long text
                for line in wrapped_text:
                    c.drawString(50, y_position, f"- {line}")
                    y_position -= 20

        c.save()
        print(f"\n✅ PDF report saved in: {pdf_filename}")

    except Exception as e:
        print(f"\n❌ Error exporting PDF report: {e}")

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
    """Prompts user to remediate the detected issue."""
    while True:
        print("\n⚠️ Would you like to remediate this issue?")
        print("1. Yes (Fix it now)")
        print("2. No (Return to main menu)")
        print("3. Exit")

        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            remediation_function(bucket_name)
            break
        elif choice == "2":
            break
        elif choice == "3":
            print("\n👋 Exiting... Stay secure!\n")
            exit()
        else:
            print("\n❌ Invalid option. Please enter 1, 2, or 3.")

def detect_public_access(bucket_name):
    """Detect if S3 bucket is publicly accessible and checks 'Block All Public Access' setting."""
    findings = {}

    # ✅ Check Bucket Policy for Public Access
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        policy_dict = json.loads(policy['Policy'])

        is_public = False
        for statement in policy_dict.get('Statement', []):
            if statement.get("Principal") == "*":
                is_public = True
                findings["public_access"] = "⚠️ WARNING: Public access is enabled!"
                findings.setdefault("recommendations", {})["public_access"] = "Disable public access by removing public policies."
                break

        if not is_public:
            findings["public_access"] = "✅ No bucket policy found (Private by default)."

    except s3.exceptions.ClientError as e:
        if 'NoSuchBucketPolicy' in str(e):
            findings["public_access"] = "✅ No bucket policy found (Private by default)."
        else:
            findings["error"] = f"❌ Error: {e}"

    # ✅ Check "Block All Public Access" Setting
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        if not all(config.values()):  # If any setting is False, it's misconfigured
            findings["block_public_access"] = "⚠️ WARNING: 'Block All Public Access' is DISABLED!"
            findings.setdefault("recommendations", {})["block_public_access"] = "Enable 'Block All Public Access' in the bucket settings."
        else:
            findings["block_public_access"] = "✅ 'Block All Public Access' is ENABLED."

    except s3.exceptions.ClientError as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            findings["block_public_access"] = "⚠️ WARNING: No 'Block All Public Access' configuration found!"
            findings.setdefault("recommendations", {})["block_public_access"] = "Manually enable 'Block All Public Access' in the bucket settings."
        else:
            findings["error"] = f"❌ Error: {e}"

    # ✅ Print initial findings BEFORE remediation
    print("\n🔍 Findings:")
    for key, value in findings.items():
        if key == "recommendations":
            print("\n⚠️ Recommended Fixes:")
            for rec_key, rec_value in value.items():
                print(f"- {rec_value}")  
        else:
            print(f"- {value}")  

    # ✅ Prompt remediation AFTER printing findings
    if "block_public_access" in findings and "⚠️" in findings["block_public_access"]:
        prompt_remediation(remediate_block_public_access, bucket_name)

        # ✅ After remediation, re-run detection to refresh findings
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        if all(config.values()):  
            findings["block_public_access"] = "✅ 'Block All Public Access' is now ENABLED."
            findings.get("recommendations", {}).pop("block_public_access", None)

    # ✅ Remove recommendations section if it's now empty
    if "recommendations" in findings and not findings["recommendations"]:
        del findings["recommendations"]

    # ✅ Print **final** findings **ONLY ONCE**
    print("\n🔍 Updated Findings:")
    for key, value in findings.items():
        if key == "recommendations":
            print("\n⚠️ Recommended Fixes:")
            for rec_key, rec_value in value.items():
                print(f"- {rec_value}")  
        else:
            print(f"- {value}")  

    return findings


def detect_missing_versioning(bucket_name):
    """Detect if S3 bucket has versioning disabled and return findings."""
    findings = {}

    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')

        if status != 'Enabled':
            findings["versioning"] = f"⚠️ WARNING: Versioning is DISABLED for '{bucket_name}'"
            findings.setdefault("recommendations", {})["versioning"] = "Enable versioning to prevent accidental data loss."
        else:
            findings["versioning"] = f"✅ Versioning is ENABLED for '{bucket_name}'"

    except s3.exceptions.ClientError as e:
        findings["error"] = f"❌ Error checking versioning: {e}"

    # ✅ Print the findings BEFORE prompting remediation
    print("\n🔍 Findings:")
    for key, value in findings.items():
        if key == "recommendations":
            print("\n⚠️ Recommended Fixes:")
            for rec_key, rec_value in value.items():
                print(f"- {rec_value}")  # ✅ Properly format recommendations
        else:
            print(f"- {value}")  # ✅ Display misconfigurations

    # ✅ Prompt for remediation after displaying findings
    if "versioning" in findings and "⚠️" in findings["versioning"]:
        prompt_remediation(remediate_missing_versioning, bucket_name)

        # ✅ After remediation, re-check versioning status
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')
        if status == "Enabled":
            findings["versioning"] = f"✅ Versioning is now ENABLED for '{bucket_name}'"
            # ✅ Remove recommendation since issue is fixed
            findings.get("recommendations", {}).pop("versioning", None)

    # ✅ Remove recommendations section if empty
    if "recommendations" in findings and not findings["recommendations"]:
        del findings["recommendations"]

    # ✅ Print final updated findings
    print("\n🔍 Updated Findings:")
    for key, value in findings.items():
        if key == "recommendations":
            print("\n⚠️ Recommended Fixes:")
            for rec_key, rec_value in value.items():
                print(f"- {rec_value}")  
        else:
            print(f"- {value}")  

    return findings


def detect_encryption(bucket_name):
    """Detects and displays whether the bucket has SSE-S3 (AES-256) encryption enabled."""
    findings = {}

    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

        if rules:
            encryption_type = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            if encryption_type == "AES256":
                findings["encryption"] = "✅ Encryption is ENABLED using SSE-S3 (AES-256)."
            else:
                findings["encryption"] = f"⚠️ WARNING: Unexpected encryption type detected: {encryption_type}"
                findings.setdefault("recommendations", {})["encryption"] = "Ensure bucket is encrypted using SSE-S3 (AES-256)."
        else:
            findings["encryption"] = "⚠️ WARNING: No encryption settings found!"
            findings.setdefault("recommendations", {})["encryption"] = "Enable AES-256 encryption for security."
    
    except s3.exceptions.ClientError as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            findings["encryption"] = "⚠️ WARNING: No encryption settings found!"
            findings.setdefault("recommendations", {})["encryption"] = "Enable AES-256 encryption for security."
        else:
            findings["error"] = f"❌ Error: {e}"
    
    return findings


def remediate_public_access(bucket_name):
    """Remediates public access by deleting bucket policy and enabling 'Block All Public Access'."""
    try:
        # ✅ Step 1: Check if a public bucket policy exists before attempting deletion
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        if policy:
            s3.delete_bucket_policy(Bucket=bucket_name)
            print(f"✅ Public access removed! Policy deleted for '{bucket_name}'.")
        else:
            print(f"ℹ️ No public bucket policy found for '{bucket_name}'. No remediation needed.")

    except s3.exceptions.ClientError as e:
        if 'NoSuchBucketPolicy' in str(e):
            print(f"ℹ️ No public bucket policy found for '{bucket_name}'. No remediation needed.")
        else:
            print(f"❌ Error: {e}")
            return

    # ✅ Step 2: Check if 'Block All Public Access' is already enabled before remediating
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        if all(config.values()):
            print(f"✅ 'Block All Public Access' is ALREADY enabled for '{bucket_name}'. No remediation needed.")
        else:
            remediate_block_public_access(bucket_name)  # Call existing function only if needed
    except s3.exceptions.ClientError as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            print(f"⚠️ No 'Block All Public Access' configuration found. Enabling now...")
            remediate_block_public_access(bucket_name)
        else:
            print(f"❌ Error: {e}")


def remediate_missing_versioning(bucket_name):
    """Enables versioning on the bucket if disabled"""
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')

        if status == "Enabled":
            print(f"✅ Versioning is ALREADY enabled for '{bucket_name}'. No remediation needed.")
        else:
            print("\n🔧 Enabling versioning ...\n")
            s3.put_bucket_versioning(
                Bucket=bucket_name, 
                VersioningConfiguration={'Status': 'Enabled'}
            )
            print(f"\n✅ Versioning enabled for '{bucket_name}'\n")
    
    except s3.exceptions.ClientError as e:
        print(f"\n❌ Error enabling versioning: {e}")

def remediate_block_public_access(bucket_name):
    """Enables 'Block All Public Access' for the bucket (Only if needed)."""
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        if all(config.values()):
            print(f"✅ 'Block All Public Access' is ALREADY enabled for '{bucket_name}'. No remediation needed.")
        else:
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
            print(f"✅ 'Block All Public Access' is now ENABLED for '{bucket_name}'!\n")
    
    except s3.exceptions.ClientError as e:
        print(f"\n❌ Error enabling 'Block All Public Access': {e}")

def remediate_missing_encryption(bucket_name):
    print("test")

def detection_menu(bucket_name):
    """Handles detection submenu"""
    while True:
        print("\n==== Detection Menu ====")
        print("1. Detect Public Access")
        print("2. Detect Missing Versioning")
        print("3. Detect Encryption Type")
        print("4. Back to Main Menu")

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            findings = detect_public_access(bucket_name)

        elif choice == "2":
            findings = detect_missing_versioning(bucket_name)

        elif choice == "3":
            findings = detect_encryption(bucket_name)

        elif choice == "4":
            return

        else:
            print("\n❌ Invalid option. Please try again.")
            continue

        # ✅ Print the findings
        print("\n🔍 Findings:")
        for key, value in findings.items():
            if key == "recommendations":
                print("\n⚠️ Recommended Fixes:")
                for rec_key, rec_value in value.items():
                    print(f"- {rec_value}")  # ✅ Properly format recommendations
            else:
                print(f"- {value}")  # ✅ No more {'key': 'value'} formatting issues

        input("\nPress Enter to return to the menu...")  # ✅ Let user review findings


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
        print(f"🔍 Scanning: {bucket_name}")
        print("1. Detection Menu 🔍")
        print("2. Remediation Menu 🔧")
        print("3. Generate Security Report 📄")
        print("4. Choose a Different Bucket 📂")
        print("5. Exit 🚪")
        print("=====================================")

        choice = input("Select an option (1-5): ").strip()

        if choice == "1":
            detection_menu(bucket_name)
        elif choice == "2":
            remediation_menu(bucket_name)
        elif choice == "3":
            findings = {}
            findings.update(detect_public_access(bucket_name))
            findings.update(detect_encryption(bucket_name))
            report_file = generate_plain_text_report(bucket_name, findings)
            #print(f"\n📄 Report saved at: {report_file}")
        elif choice == "4":
            bucket_name = list_buckets()
            if not bucket_name:
                print("\n❌ Exiting... No bucket selected.")
                return
        elif choice == "5":
            print("\n👋 Exiting... Stay secure!\n")
            break
        else:
            print("\n❌ Invalid option. Please try again.")

if __name__ == "__main__":
    main()