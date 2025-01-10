import psycopg2
from psycopg2 import sql
from data.config import staging_config


def create_database_and_user(db_name, new_user, new_password, admin_user, admin_password,admin_db, host='localhost', port='5432'):
    # Connect to the PostgreSQL server using admin credentials
    conn = psycopg2.connect(dbname=admin_db, user=admin_user, password=admin_password, host=host, port=port)
    conn.autocommit = True  # Enable autocommit to create databases and users

    try:
        # Create a cursor object
        cursor = conn.cursor()

        # Check if the new user exists
        cursor.execute(sql.SQL("SELECT 1 FROM pg_roles WHERE rolname = %s"), [new_user])
        user_exists = cursor.fetchone()

        if not user_exists:
            # Create the new user if it does not exist
            cursor.execute(sql.SQL("CREATE USER {} WITH PASSWORD %s").format(sql.Identifier(new_user)), [new_password])
            print(f"User '{new_user}' created successfully.")
        else:
            print(f"User '{new_user}' already exists.")

        # Check if the database exists
        cursor.execute(sql.SQL("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s"), [db_name])
        db_exists = cursor.fetchone()

        if not db_exists:
            # Create the database if it does not exist
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
            print(f"Database '{db_name}' created successfully.")
        else:
            print(f"Database '{db_name}' already exists.")

        # Grant all privileges on the new database to the new user
        cursor.execute(sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {}").format(sql.Identifier(db_name), sql.Identifier(new_user)))
        print(f"Granted all privileges on '{db_name}' to user '{new_user}'.")

    except Exception as e:
        print(f"An error occurred: {e}")
    
    finally:
        # Close the cursor and connection
        cursor.close()
        conn.close()

if __name__ == "__main__":
    DMZ_DIC = staging_config(section="mdl_dmz")
    PE_DIC = staging_config(section="cd_crossfeed")
    # Database connection parameters
    DB_NAME = str(DMZ_DIC.get("mdl_database"))  # Name of the database to create
    NEW_USER = str(DMZ_DIC.get("mdl_user"))      # New PostgreSQL username
    NEW_PASSWORD = str(DMZ_DIC.get("mdl_password")) # New PostgreSQL password
    ADMIN_USER = str(PE_DIC.get("user")) # Admin PostgreSQL username
    ADMIN_PASSWORD = str(PE_DIC.get("password")) # Admin PostgreSQL password
    ADMIN_DB = str(PE_DIC.get("database"))
    HOST = str(DMZ_DIC.get("mdl_host")) # Host where PostgreSQL is running
    PORT = str(DMZ_DIC.get("mdl_port")) # Port on which PostgreSQL is listening
    
    create_database_and_user(DB_NAME, NEW_USER, NEW_PASSWORD, ADMIN_USER, ADMIN_PASSWORD, ADMIN_DB, HOST, PORT)
