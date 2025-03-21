from flask import Flask, request, redirect, jsonify, render_template, session, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from pymongo import MongoClient
import secrets
import jwt
import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# MongoDB setup
client = MongoClient("mongodb+srv://neel:h6yoMVxNBiBfpqOl@cluster0.iavsk.mongodb.net/")
db = client["buddy-deals"]
users_collection = db["users"]
clients_collection = db["clients"]
auth_codes_collection = db["auth_codes"]

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    user = users_collection.find_one({"_id": user_id})
    return User(user_id) if user else None

@app.route("/auth")
def auth():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    
    client = clients_collection.find_one({"client_id": client_id, "redirect_uri": redirect_uri})
    if not client:
        return "Invalid client", 400
    
    session["client_id"] = client_id
    session["redirect_uri"] = redirect_uri
    return render_template("login.html")  # Show login popup

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    print(username, password)
    user = users_collection.find_one({"email": username, "password": password})
    print(user)
    if user:
        login_user(User(user["_id"]))
        code = secrets.token_urlsafe(16)
        auth_codes_collection.insert_one({"code": code, "user_id": user["_id"]})
        return redirect(f"{session['redirect_uri']}?code={code}")
    return "Invalid credentials", 401

@app.route("/token", methods=["POST"])
def token():
    code = request.json.get("code")
    client_id = request.json.get("client_id")
    
    auth_entry = auth_codes_collection.find_one({"code": code})
    client = clients_collection.find_one({"client_id": client_id})
    if not auth_entry or not client:
        return jsonify({"error": "Invalid code or client"}), 400
    
    user = users_collection.find_one({"_id": auth_entry["user_id"]})
    auth_codes_collection.delete_one({"code": code})  # Remove used code
    
    access_token = jwt.encode({
        "sub": str(user["_id"]),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.secret_key, algorithm="HS256")
    
    return jsonify({"access_token": access_token, "user": {"username": user["username"], "email": user["email"]}})

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return "Logged out"

if __name__ == "__main__":
    app.run(port=8001)
