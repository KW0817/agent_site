import os
import pymysql
import time

# Database configuration (same as in server.py)
db_config = {
    "host": "interchange.proxy.rlwy.net",
    "port": 3306,
    "user": "root",
    "password": "HoqhkLPJdxgzSCjaUCnrYdQvwOeaFxXm",
    "database": "railway"
}

def execute_sql_file(file_path, conn):
    """Execute SQL statements from a file"""
    try:
        with open(file_path, 'r') as f:
            sql_script = f.read()
        
        # Split script into individual statements
        statements = sql_script.split(';')
        
        cursor = conn.cursor()
        for statement in statements:
            # Skip empty statements
            if statement.strip():
                cursor.execute(statement)
        
        conn.commit()
        cursor.close()
        print(f"✅ Successfully executed: {file_path}")
        return True
    except Exception as e:
        print(f"❌ Error executing {file_path}: {e}")
        return False

def init_database():
    """Initialize database with migration scripts"""
    try:
        # Try to connect to the database
        print("Connecting to database...")
        max_retries = 5
        retries = 0
        
        while retries < max_retries:
            try:
                conn = pymysql.connect(**db_config)
                break
            except Exception as e:
                retries += 1
                if retries >= max_retries:
                    raise e
                print(f"Connection failed, retrying in 5 seconds... ({retries}/{max_retries})")
                time.sleep(5)
        
        # Get all migration scripts
        migration_dir = os.path.join(os.path.dirname(__file__), 'sql', 'migrations')
        migration_files = [f for f in os.listdir(migration_dir) if f.endswith('.sql')]
        migration_files.sort()  # Sort to run in correct order
        
        # Execute each migration script
        for migration_file in migration_files:
            file_path = os.path.join(migration_dir, migration_file)
            execute_sql_file(file_path, conn)
        
        conn.close()
        print("✅ Database initialization completed")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

if __name__ == "__main__":
    init_database()