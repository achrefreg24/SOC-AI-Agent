import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import sys
import getpass

print("=========================================")
print("  PostgreSQL SOC Database Setup Script")
print("=========================================")
print("\nThis script will automatically create the 'soc_db' database and 'soc_user' role.")
print("It requires the superuser password you set when installing PostgreSQL.")

superuser_pass = getpass.getpass("\nEnter the password for the 'postgres' user: ")

try:
    print("\nConnecting to PostgreSQL...")
    conn = psycopg2.connect(
        dbname='postgres', 
        user='postgres', 
        password=superuser_pass, 
        host='localhost',
        port=5432
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()

    # Create the user
    try:
        print("[*] Creating user 'soc_user'...")
        cursor.execute("CREATE USER soc_user WITH PASSWORD 'soc_secret';")
        print("  -> User created.")
    except psycopg2.errors.DuplicateObject:
        print("  -> User 'soc_user' already exists. Skipping.")

    # Create the database
    try:
        print("[*] Creating database 'soc_db'...")
        cursor.execute("CREATE DATABASE soc_db OWNER soc_user;")
        print("  -> Database created.")
    except psycopg2.errors.DuplicateDatabase:
        print("  -> Database 'soc_db' already exists. Skipping.")

    conn.close()
    print("\n✅ Setup Complete! Your PostgreSQL server is now ready for the AI SOC.")
    
except Exception as e:
    print(f"\n❌ Error: Could not connect or setup database. {e}")
    print("Ensure PostgreSQL is installed and running on port 5432.")
