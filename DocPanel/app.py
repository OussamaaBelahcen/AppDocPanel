


import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import bcrypt
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta

# Charger les variables d'environnement
load_dotenv()

# -------------------------------------------------------------------
# VARIABLES D'ENVIRONNEMENT (SÉCURISÉES)
# -------------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

required_vars = [SUPABASE_URL, SUPABASE_KEY, SECRET_KEY]
if not all(required_vars):
    raise ValueError("Des variables d'environnement manquantes. Vérifiez votre fichier .env")

# -------------------------------------------------------------------
# INIT FLASK + SUPABASE
# -------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    test = supabase.table("users").select("count", count="exact").execute()
    print(f"✅ Connexion à Supabase réussie. Nombre d'utilisateurs : {test.count}")
except Exception as e:
    print(f"❌ ERREUR de connexion à Supabase au démarrage : {e}")

# -------------------------------------------------------------------
# UTILITAIRES
# -------------------------------------------------------------------
def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email)

def validate_bilingual_data(data):
    errors = []
    bilingual_fields = {
        'nom_fr': 'Nom (Français)',
        'nom_ar': 'الاسم (عربي)',
        'prenom_fr': 'Prénom (Français)',
        'prenom_ar': 'الاسم الأول (عربي)',
        'specialite_fr': 'Spécialité (Français)',
        'specialite_ar': 'التخصص (عربي)',
        'ville_fr': 'Ville (Français)',
        'ville_ar': 'المدينة (عربي)',
        'quartier_fr': 'Quartier (Français)',
        'quartier_ar': 'الحي (عربي)',
        'adresse_fr': 'Adresse (Français)',
        'adresse_ar': 'العنوان (عربي)',
        'type_diplome_fr': 'Type de diplôme (Français)',
        'type_diplome_ar': 'نوع الشهادة (عربي)',
        'secteur_fr': 'Secteur (Français)',
        'secteur_ar': 'القطاع (عربي)',
        'activite_fr': 'Activité (Français)',
        'activite_ar': 'النشاط (عربي)'
    }
    for field, label in bilingual_fields.items():
        if not data.get(field, '').strip():
            errors.append(f"{label} est obligatoire")
    standard_fields = {'tel': 'Téléphone', 'email': 'Email'}
    for field, label in standard_fields.items():
        if not data.get(field, '').strip():
            errors.append(f"{label} est obligatoire")
    return errors

def has_arabic_characters(text):
    arabic_pattern = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
    return bool(arabic_pattern.search(text))

def has_french_characters(text):
    french_pattern = re.compile(r'[a-zA-ZàâäéèêëïîôöùûüÿçÀÂÄÉÈÊËÏÎÔÖÙÛÜŸÇ]')
    return bool(french_pattern.search(text))

def validate_language_content(data):
    errors = []
    french_fields = ['nom_fr', 'prenom_fr', 'specialite_fr', 'ville_fr', 'quartier_fr',
                     'adresse_fr', 'type_diplome_fr', 'secteur_fr', 'activite_fr']
    for field in french_fields:
        value = data.get(field, '').strip()
        if value and not has_french_characters(value):
            errors.append(f"Le champ {field.replace('_fr', ' (Français)')} doit contenir du texte en français")
    arabic_fields = ['nom_ar', 'prenom_ar', 'specialite_ar', 'ville_ar', 'quartier_ar',
                     'adresse_ar', 'type_diplome_ar', 'secteur_ar', 'activite_ar']
    for field in arabic_fields:
        value = data.get(field, '').strip()
        if value and not has_arabic_characters(value):
            errors.append(f"Le champ {field.replace('_ar', ' (العربية)')} doit contenir du texte en arabe")
    return errors

# -------------------------------------------------------------------
# ROUTES PRINCIPALES
# -------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else "login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        confirm_pwd = request.form.get("confirm_password", "")
        if not email or not pwd or not confirm_pwd:
            flash("Tous les champs sont requis.", "error")
            return render_template("register.html")
        if not is_valid_email(email):
            flash("Email invalide.", "error")
            return render_template("register.html")
        if pwd != confirm_pwd:
            flash("Les mots de passe ne correspondent pas.", "error")
            return render_template("register.html")
        if len(pwd) < 6:
            flash("Le mot de passe doit faire au moins 6 caractères.", "error")
            return render_template("register.html")
        try:
            exists = supabase.table("users").select("id").eq("email", email).execute()
            if exists.data and len(exists.data) > 0:
                flash("Email déjà utilisé.", "error")
                return render_template("register.html")
            pwd_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            user_data = {
                "email": email,
                "password_hash": pwd_hash,
                "language": "both",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "profile_data": {},
                "calendar": {}
            }
            result = supabase.table("users").insert(user_data).execute()
            if not result.data or len(result.data) == 0:
                flash("Erreur inconnue lors de l'inscription. Veuillez réessayer.", "error")
                return render_template("register.html")
            flash("Inscription réussie ! Connectez-vous maintenant.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"❌ ERREUR lors de l'inscription de {email}: {type(e).__name__}: {e}")
            flash("Erreur technique lors de l'inscription. Veuillez réessayer plus tard.", "error")
            return render_template("register.html")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        if not email or not pwd:
            flash("Email et mot de passe requis.", "error")
            return render_template("login.html")
        try:
            res = supabase.table("users").select("*").eq("email", email).execute()
            if res.data and len(res.data) > 0:
                user = res.data[0]
                if bcrypt.checkpw(pwd.encode(), user["password_hash"].encode()):
                    session.update({
                        "user_id": user["id"],
                        "email": email,
                        "language": user.get("language", "both"),
                        "profile_data": user.get("profile_data", {}),
                        "calendar": user.get("calendar", {})
                    })
                    flash("Connexion réussie.", "success")
                    return redirect(url_for("dashboard"))
                else:
                    flash("Identifiants invalides.", "error")
            else:
                flash("Identifiants invalides.", "error")
        except Exception as e:
            print(f"❌ ERREUR lors de la connexion de {email}: {e}")
            flash("Erreur technique. Veuillez réessayer.", "error")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", profile_data=session.get("profile_data", {}), calendar=session.get("calendar", {}))

@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        data = {k: request.form.get(k, "").strip() for k in [
            "nom_fr", "nom_ar", "prenom_fr", "prenom_ar",
            "specialite_fr", "specialite_ar", "ville_fr", "ville_ar",
            "quartier_fr", "quartier_ar", "adresse_fr", "adresse_ar",
            "type_diplome_fr", "type_diplome_ar", "secteur_fr", "secteur_ar",
            "activite_fr", "activite_ar", "tel", "email"
        ]}
        validation_errors = validate_bilingual_data(data)
        language_errors = validate_language_content(data)
        all_errors = validation_errors + language_errors
        if all_errors:
            for error in all_errors:
                flash(error, "error")
            return render_template("edit_profile.html", data=data)
        try:
            updated_profile_data = {
                "nom": {"fr": data["nom_fr"], "ar": data["nom_ar"]},
                "prenom": {"fr": data["prenom_fr"], "ar": data["prenom_ar"]},
                "specialite": {"fr": data["specialite_fr"], "ar": data["specialite_ar"]},
                "ville": {"fr": data["ville_fr"], "ar": data["ville_ar"]},
                "quartier": {"fr": data["quartier_fr"], "ar": data["quartier_ar"]},
                "adresse": {"fr": data["adresse_fr"], "ar": data["adresse_ar"]},
                "type_diplome": {"fr": data["type_diplome_fr"], "ar": data["type_diplome_ar"]},
                "secteur": {"fr": data["secteur_fr"], "ar": data["secteur_ar"]},
                "activite": {"fr": data["activite_fr"], "ar": data["activite_ar"]},
                "tel": data["tel"],
                "email": data["email"]
            }
            result = supabase.table("users").update({
                "profile_data": updated_profile_data,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", session["user_id"]).execute()
            if result.data and len(result.data) > 0:
                session["profile_data"] = updated_profile_data
                session["email"] = data["email"]
                flash("Profil mis à jour avec succès.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Erreur lors de la mise à jour.", "error")
        except Exception as e:
            print(f"❌ ERREUR mise à jour profil utilisateur {session['user_id']}: {e}")
            flash("Erreur technique lors de la mise à jour.", "error")
    profile_data = session.get("profile_data", {})
    form_data = {}
    for field in ["nom", "prenom", "specialite", "ville", "quartier", "adresse",
                  "type_diplome", "secteur", "activite"]:
        if field in profile_data:
            form_data[f"{field}_fr"] = profile_data[field].get("fr", "")
            form_data[f"{field}_ar"] = profile_data[field].get("ar", "")
    form_data["tel"] = profile_data.get("tel", "")
    form_data["email"] = session.get("email", "")
    return render_template("edit_profile.html", data=form_data)

# ✅ Route corrigée : récupère les réservations depuis patients
@app.route("/calendar/edit", methods=["GET"])
def edit_calendar():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    try:
        doctor_id = session["user_id"]
        patients_resp = supabase.table("patients").select("*").eq("doctor_id", doctor_id).execute()
        reservations = []
        if patients_resp.data:
            for p in patients_resp.data:
                date = p.get("patient_date_reservation")
                time = p.get("patient_time_reservation")
                if not date or not time:
                    continue
                start_iso = f"{date}T{time}"
                end_dt = datetime.fromisoformat(start_iso) + timedelta(minutes=30)
                end_iso = end_dt.isoformat()
                reservations.append({
                    "patient_id": p["id"],
                    "patient_name": p.get("patient_nom", "Patient"),
                    "patient_phone": p.get("patient_telephone", "Non fourni"),
                    "patient_email": p.get("patient_email", "Non fourni"),
                    "start": start_iso,
                    "end": end_iso,
                    "status": p.get("status", "reserved"),
                    "date": str(date),
                    "time": time
                })
        return render_template("edit_calendar.html", reservations=reservations)
    except Exception as e:
        print(f"❌ ERREUR chargement réservations: {e}")
        flash("Erreur lors du chargement des rendez-vous.", "error")
        return redirect(url_for("dashboard"))

# -------------------------------------------------------------------
# API - GESTION DES RENDEZ-VOUS
# -------------------------------------------------------------------
@app.route("/api/events")
def api_events():
    if "user_id" not in session:
        return jsonify([])

    doctor_id = session.get("user_id")
    if not doctor_id:
        return jsonify([])

    try:
        # Réservations
        patients_resp = supabase.table("patients").select("*").eq("doctor_id", doctor_id).execute()
        reserved_events = {}
        if patients_resp.data:
            for p in patients_resp.data:
                date = p.get("patient_date_reservation")
                time = p.get("patient_time_reservation")
                if not date or not time:
                    continue
                start = f"{date}T{time}"
                end_dt = datetime.fromisoformat(start) + timedelta(minutes=30)
                end = end_dt.isoformat()
                reserved_events[start] = {
                    "id": f"patient_{p['id']}",
                    "title": f"{p.get('patient_nom', 'Patient')}",
                    "start": start,
                    "end": end,
                    "color": "#ffc107",
                    "borderColor": "#e0a800",
                    "textColor": "#212529",
                    "status": "reserved",
                    "extendedProps": {
                        "type": "reservation",
                        "patient_id": p["id"],
                        "patient_name": p.get("patient_nom", ""),
                        "patient_phone": p.get("patient_telephone", ""),
                        "patient_email": p.get("patient_email", ""),
                        "date": str(date),
                        "time": time
                    }
                }

        # Créneaux disponibles
        events = []
        calendar = session.get("calendar", {})
        for week_date, slots in calendar.items():
            if not isinstance(slots, list):
                continue
            for slot in slots:
                if isinstance(slot, dict) and "start" in slot:
                    start = slot["start"]
                    if start in reserved_events:
                        continue
                    events.append({
                        "id": f"slot_{start}",
                        "title": "Disponible",
                        "start": start,
                        "end": slot["end"],
                        "color": "#d1ecf1",
                        "borderColor": "#bee5eb",
                        "textColor": "#0c5460",
                        "status": "available",
                        "extendedProps": {"type": "slot"}
                    })

        events.extend(reserved_events.values())
        return jsonify(events)

    except Exception as e:
        print(f"❌ ERREUR chargement événements: {e}")
        return jsonify([])

# ✅ Confirmer
@app.route("/api/confirm_reservation/<patient_id>", methods=["POST"])
def api_confirm_reservation(patient_id):
    if "user_id" not in session:
        return jsonify({"error": "Non autorisé"}), 401
    try:
        # Vérifier que le patient existe et appartient au médecin
        doctor_id = session["user_id"]
        check = supabase.table("patients").select("id").eq("id", patient_id).eq("doctor_id", doctor_id).execute()
        if not check.data or len(check.data) == 0:
            return jsonify({"error": "Rendez-vous non trouvé"}), 404

        supabase.table("patients").update({
            "status": "confirmed",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", patient_id).execute()
        return jsonify({"message": "Rendez-vous confirmé"})
    except Exception as e:
        print(f"❌ ERREUR confirmation: {e}")
        return jsonify({"error": "Erreur technique"}), 500

# 🔄 Reporter
@app.route("/api/reschedule_reservation/<patient_id>", methods=["POST"])
def api_reschedule_reservation(patient_id):
    if "user_id" not in session:
        return jsonify({"error": "Non autorisé"}), 401
    data = request.get_json()
    new_date = data.get("new_date")
    new_time = data.get("new_time")
    if not new_date or not new_time:
        return jsonify({"error": "Nouvelle date et heure requises"}), 400
    try:
        doctor_id = session["user_id"]
        check = supabase.table("patients").select("id").eq("id", patient_id).eq("doctor_id", doctor_id).execute()
        if not check.data or len(check.data) == 0:
            return jsonify({"error": "Rendez-vous non trouvé"}), 404

        supabase.table("patients").update({
            "patient_date_reservation": new_date,
            "patient_time_reservation": new_time,
            "status": "rescheduled",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", patient_id).execute()
        return jsonify({"message": "Rendez-vous reporté"})
    except Exception as e:
        print(f"❌ ERREUR report: {e}")
        return jsonify({"error": "Erreur technique"}), 500

# 🗑️ Supprimer
@app.route("/api/delete_reservation/<patient_id>", methods=["DELETE"])
def api_delete_reservation(patient_id):
    if "user_id" not in session:
        return jsonify({"error": "Non autorisé"}), 401
    try:
        doctor_id = session["user_id"]
        check = supabase.table("patients").select("id").eq("id", patient_id).eq("doctor_id", doctor_id).execute()
        if not check.data or len(check.data) == 0:
            return jsonify({"error": "Rendez-vous non trouvé"}), 404

        supabase.table("patients").delete().eq("id", patient_id).execute()
        return jsonify({"message": "Rendez-vous supprimé"})
    except Exception as e:
        print(f"❌ ERREUR suppression: {e}")
        return jsonify({"error": "Erreur technique"}), 500

# -------------------------------------------------------------------
# AUTRES ROUTES
# -------------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for("login"))

@app.route("/set_language/<lang>")
def set_language(lang):
    if lang in ["fr", "ar", "both"]:
        session["display_language"] = lang
        flash(f"Langue d'affichage changée vers: {lang}", "info")
    return redirect(request.referrer or url_for("dashboard"))
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=8000, debug=True)
