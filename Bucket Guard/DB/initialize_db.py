import sqlite3

# connection to the database
conn = sqlite3.connect(r"D:\TKH COV\awsCLI\BucketGuard\Bucket Guard\DB\bucketguard.db")
cursor = conn.cursor()

# Create misconfigurations table
cursor.execute("""
CREATE TABLE IF NOT EXISTS misconfigurations(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue TEXT UNIQUE NOT NULL,
    remediation_code TEXT NOT NULL,
    cis_reference TEXT NOT NULL
);

""")

# Commit changes and close conn
conn.commit()
conn.close()

print("Database & Table created successfully!")