from flask import Flask, request
from sqlalchemy.orm import Session
from models import Account

app = Flask(__name__)


@app.route("/account")
def account():
    email = request.args.get("email", "")
    session = Session()
    row = session.query(Account).filter(Account.email == email).first()
    return row.display_name if row else "not found"
