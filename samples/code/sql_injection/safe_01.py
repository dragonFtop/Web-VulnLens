from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchone())
