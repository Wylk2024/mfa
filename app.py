from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyotp, qrcode, io, base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-secret-in-production"

# Simple in-memory user store for demo purposes.
# In production, use a database.
users = {}
# users structure:
# users[username] = {"password": hashed_password, "mfa_secret": base32secret}

def qrcode_data_uri(data):
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return "data:image/png;base64," + b64

@app.route("/")
def index():
    if session.get("username") and session.get("mfa_validated"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            flash("Usuário e senha são obrigatórios.", "danger")
            return redirect(url_for("register"))
        if username in users:
            flash("Usuário já existe.", "warning")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password)
        secret = pyotp.random_base32()
        users[username] = {"password": hashed, "mfa_secret": secret}
        # Create provisioning URI for authenticator apps
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FlaskMFA-Render")
        img_uri = qrcode_data_uri(uri)
        return render_template("mfa_setup.html", img_uri=img_uri, secret=secret, username=username)
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = users.get(username)
        if not user or not check_password_hash(user["password"], password):
            flash("Usuário ou senha inválidos.", "danger")
            return redirect(url_for("login"))
        # Save username to session and require MFA validation
        session["username"] = username
        session["mfa_validated"] = False
        return redirect(url_for("mfa_verify"))
    return render_template("login.html")

@app.route("/mfa_verify", methods=["GET", "POST"])
def mfa_verify():
    username = session.get("username")
    if not username:
        flash("Faça login primeiro.", "warning")
        return redirect(url_for("login"))
    user = users.get(username)
    if request.method == "POST":
        code = request.form["code"].strip()
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(code, valid_window=1):
            session["mfa_validated"] = True
            flash("Autenticação por MFA validada com sucesso!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Código inválido. Tente novamente.", "danger")
            return redirect(url_for("mfa_verify"))
    return render_template("mfa_verify.html", username=username)

@app.route("/dashboard")
def dashboard():
    if not (session.get("username") and session.get("mfa_validated")):
        flash("Acesso negado. Faça login e valide o MFA.", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Desconectado.", "info")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)