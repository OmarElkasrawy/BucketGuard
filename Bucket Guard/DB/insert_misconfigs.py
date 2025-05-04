import sqlite3

# Connect to the database
conn = sqlite3.connect(r"D:\TKH COV\awsCLI\BucketGuard\Bucket Guard\DB\bucketguard.db")
cursor = conn.cursor()

# Updated misconfigurations list
misconfigurations = [
    ("Public access is enabled", "remediate_public_access", "CIS AWS Foundations Benchmark S3.8"),
    ("Versioning is disabled", "remediate_missing_versioning", "CIS AWS Foundations Benchmark S3.14"),
    ("Block Public Access is disabled", "remediate_block_public_access", "CIS AWS Foundations Benchmark S3.1")
]

# Insert new records or update existing ones
for issue, remediation, cis in misconfigurations:
    cursor.execute("""
        INSERT INTO misconfigurations (issue, remediation_code, cis_reference)
        VALUES (?, ?, ?)
        ON CONFLICT(issue) DO UPDATE 
        SET remediation_code = excluded.remediation_code,
            cis_reference = excluded.cis_reference;
    """, (issue, remediation, cis))

# Commit changes and close
conn.commit()
conn.close()

print("Misconfigurations updated successfully!")
