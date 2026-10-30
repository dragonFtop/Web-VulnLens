from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    sql = "SELECT id, title FROM articles WHERE title LIKE '%" + keyword + "%'"
    cursor.execute(sql)
    return str(cursor.fetchall())
