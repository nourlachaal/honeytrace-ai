
import os

import psycopg
from dotenv import load_dotenv

print("Starting HoneyTrace database connection test...")

load_dotenv()

database_url = os.getenv("DATABASE_URL")

if not database_url:
    raise RuntimeError("DATABASE_URL is missing from .env")

print("DATABASE_URL found. Connecting to PostgreSQL...")

with psycopg.connect(database_url, connect_timeout=5) as connection:
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_user, version()")
        database, user, version = cursor.fetchone()

        print(f"Database: {database}")
        print(f"User: {user}")
        print(f"PostgreSQL: {version.split(',')[0]}")
        print("Connection successful!")
