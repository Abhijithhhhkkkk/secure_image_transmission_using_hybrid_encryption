from flask import Flask, render_template, session, redirect, url_for, request, abort, flash
from pathlib import Path
from datetime import datetime
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = "40e489539a4adbff3da7da796b128b8ac5128dcb0b3494ik8c1c7d9d847d61867dd"

BASE_DIR = Path(__file__).resolve().parent
DECRYPTED_FOLDER = BASE_DIR / "static" / "images"
DECRYPTED_FOLDER.mkdir(parents=True, exist_ok=True)

USERNAME = "admin"
PASSWORD_HASH ="scrypt:32768:8:1$ehRnpHbASUYjpfTf$1bf7d2173dc777bd54828c2c693d2f15d5f08b463e149b5c327839de6fe5ad5da40a779df33968bacb126e2cbc3f24fc5f47eb0b116b442d9b6acae372497c6c"

def sanitize_name(name: str) -> str:
    allowed = []
    for ch in name.strip():
        if ch.isalnum() or ch in (" ", "_", "-"):
            allowed.append(ch)
    cleaned = "".join(allowed).strip()
    return cleaned if cleaned else "unknown_patient"


def format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d-%m-%Y %I:%M %p")


def is_logged_in() -> bool:
    return "user" in session


def get_image_files(folder: Path):
    if not folder.exists() or not folder.is_dir():
        return []

    files = []
    for f in folder.iterdir():
        if f.is_file() and f.suffix.lower() in [".jpg", ".jpeg", ".png"]:
            files.append(f)

    files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return files


def get_patient_folders(search_term: str = ""):
    if not DECRYPTED_FOLDER.exists():
        return []

    patients = []

    for item in DECRYPTED_FOLDER.iterdir():
        if not item.is_dir():
            continue

        patient_name = item.name
        image_files = get_image_files(item)

        if search_term and search_term.lower() not in patient_name.lower():
            continue

        preview_image = None
        latest_upload = None

        if image_files:
            preview_image = image_files[0].name
            latest_upload = format_timestamp(image_files[0].stat().st_mtime)

        patients.append({
            "name": patient_name,
            "count": len(image_files),
            "preview_image": preview_image,
            "latest_upload": latest_upload,
        })

    patients.sort(key=lambda x: x["name"].lower())
    return patients


def get_images_for_patient(patient_name: str):
    patient_name = sanitize_name(patient_name)
    patient_folder = DECRYPTED_FOLDER / patient_name

    if not patient_folder.exists() or not patient_folder.is_dir():
        return []

    images = []
    for f in get_image_files(patient_folder):
        images.append({
            "name": f.name,
            "uploaded_at": format_timestamp(f.stat().st_mtime),
            "size_kb": round(f.stat().st_size / 1024, 2),
        })

    return images


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
            session["user"] = USERNAME
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()
    patients = get_patient_folders(search)

    total_patients = len(patients)
    total_images = sum(p["count"] for p in patients)

    return render_template(
        "dashboard.html",
        patients=patients,
        user=session["user"],
        total_patients=total_patients,
        total_images=total_images,
        search=search,
    )


@app.route("/patient/<path:patient_name>")
def patient_view(patient_name):
    if not is_logged_in():
        return redirect(url_for("login"))

    safe_name = sanitize_name(patient_name)
    images = get_images_for_patient(safe_name)

    if not images and not (DECRYPTED_FOLDER / safe_name).exists():
        abort(404)

    return render_template(
        "patient.html",
        patient_name=safe_name,
        images=images,
        user=session["user"],
    )


@app.route("/delete-image/<path:patient_name>/<path:image_name>", methods=["POST"])
def delete_image(patient_name, image_name):
    if not is_logged_in():
        return redirect(url_for("login"))

    safe_patient = sanitize_name(patient_name)
    patient_folder = DECRYPTED_FOLDER / safe_patient
    image_path = patient_folder / Path(image_name).name

    if image_path.exists() and image_path.is_file():
        image_path.unlink()
        flash("Image deleted successfully.", "success")
    else:
        flash("Image not found.", "error")

    return redirect(url_for("patient_view", patient_name=safe_patient))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=8000)
