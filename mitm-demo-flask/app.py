from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from db import get_connection, init_db

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
COOKIE_NAME = "session_id"


def create_app(mode="http"):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "demo-secret-key"
    app.config["MODE"] = mode
    app.config["DB_PATH"] = str(BASE_DIR / "app.db")
    app.config["UPLOAD_DIR"] = str(UPLOAD_DIR)
    app.config["ENABLE_HSTS"] = mode == "https_hsts"

    UPLOAD_DIR.mkdir(exist_ok=True)
    init_db()

    @app.before_request
    def load_logged_in_user():
        session_id = request.cookies.get(COOKIE_NAME)
        g.user = None
        if not session_id:
            return
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT users.id, users.username
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row:
            g.user = {"id": row["id"], "username": row["username"]}

    @app.after_request
    def set_hsts_header(response):
        if app.config["ENABLE_HSTS"]:
            response.headers["Strict-Transport-Security"] = "max-age=60"
        return response

    def require_auth():
        if g.user is None:
            return redirect(url_for("login"))
        return None

    @app.route("/")
    def dashboard():
        unauth = require_auth()
        if unauth:
            return unauth

        with get_connection() as conn:
            files = conn.execute(
                """
                SELECT id, filename, upload_time
                FROM files
                WHERE user_id = ?
                ORDER BY id DESC
                """,
                (g.user["id"],),
            ).fetchall()

        return render_template("dashboard.html", files=files)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                flash("Username and password are required.", "error")
                return render_template("register.html")

            try:
                with get_connection() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, password),
                    )
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except Exception:
                flash("Username already exists.", "error")

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            with get_connection() as conn:
                user = conn.execute(
                    "SELECT id, username FROM users WHERE username = ? AND password = ?",
                    (username, password),
                ).fetchone()

                if not user:
                    flash("Invalid credentials.", "error")
                    return render_template("login.html")

                session_id = str(uuid4())
                conn.execute(
                    "INSERT INTO sessions (session_id, user_id, created_at) VALUES (?, ?, ?)",
                    (
                        session_id,
                        user["id"],
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

            response = redirect(url_for("dashboard"))
            response.set_cookie(
                COOKIE_NAME,
                session_id,
                secure=False,
                httponly=False,
                samesite=None,
            )
            return response

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session_id = request.cookies.get(COOKIE_NAME)
        if session_id:
            with get_connection() as conn:
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

        response = redirect(url_for("login"))
        response.delete_cookie(COOKIE_NAME)
        return response

    @app.route("/upload", methods=["POST"])
    def upload():
        unauth = require_auth()
        if unauth:
            return unauth

        incoming = request.files.getlist("files")
        if not incoming or all(file.filename == "" for file in incoming):
            flash("Select at least one file.", "error")
            return redirect(url_for("dashboard"))

        with get_connection() as conn:
            for item in incoming:
                if not item or item.filename == "":
                    continue

                original_name = secure_filename(item.filename)
                if not original_name:
                    continue

                stored_name = f"{uuid4()}_{original_name}"
                destination = UPLOAD_DIR / stored_name
                item.save(destination)

                conn.execute(
                    """
                    INSERT INTO files (user_id, filename, filepath, upload_time)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        g.user["id"],
                        original_name,
                        str(destination),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

        flash("File(s) uploaded successfully.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/files/<int:file_id>")
    def get_file(file_id):
        unauth = require_auth()
        if unauth:
            return unauth

        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT filename, filepath
                FROM files
                WHERE id = ? AND user_id = ?
                """,
                (file_id, g.user["id"]),
            ).fetchone()

        if not row:
            abort(404)

        file_path = Path(row["filepath"])
        if not file_path.exists():
            abort(404)

        return send_file(file_path, download_name=row["filename"], as_attachment=False)

    return app


if __name__ == "__main__":
    application = create_app(mode="http")
    application.run(host="0.0.0.0", port=5000, debug=True)
