from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM accounts WHERE username = '{}' AND password = '{}'".format(
            username, password
        )
    )
    return "ok"
