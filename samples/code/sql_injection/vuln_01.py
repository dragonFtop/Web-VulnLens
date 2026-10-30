from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/users")
def list_users():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name FROM users WHERE name = '{name}'")
    return str(cursor.fetchall())
