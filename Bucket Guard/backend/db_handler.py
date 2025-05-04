import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), '../DB/bucketguard.db')

def get_misconfigurations():
    """Fetches all misconfigs from the database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT issue, remediation_code, cis_reference FROM misconfigurations")
    misconfigurations = cursor.fetchall()
    conn.close()
    return misconfigurations