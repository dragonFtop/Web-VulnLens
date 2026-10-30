from flask import Flask, request
import sqlite3

app = Flask(__name__)
ALLOWED_COLUMNS = {"name": "name", "email": "email", "created_at": "created_at"}


@app.route("/users/sort")
def sorted_users():
    requested = request.args.get("sort", "name")
    column = ALLOWED_COLUMNS.get(requested, "name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name FROM users ORDER BY {column} LIMIT 50")
    return str(cursor.fetchall())
