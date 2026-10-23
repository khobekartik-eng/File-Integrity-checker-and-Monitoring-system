import sqlite3


# Database se connection
connection = sqlite3.connect("integrity.db")

# Cursor create
cursor = connection.cursor()


# Evidence table create
cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    original_hash TEXT NOT NULL,
    current_hash TEXT,
    status TEXT,
    created_at TEXT,
    checked_at TEXT
)
""")


# Changes save karo
connection.commit()


# Connection close
connection.close()


print("Database created successfully!")