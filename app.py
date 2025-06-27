from flask import Flask, render_template, request, redirect, url_for, session, flash
from A2ApiLib import CollectStations, ConfigReadStation, ConfigSendStation
from dotenv import load_dotenv
from functools import wraps
import requests
import os
import json

# Load environment variables
load_dotenv()

# Config
API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXlfaWQiOiIyNWRhNWQ2Ny1mYmZjLTQ4NGMtOTM4My1iMmY1MjE3OWJkMDkiLCJrZXlfdHlwZSI6InNlcnZpY2UiLCJvd25lcl9pZCI6IjcyMDU2MjMxOTI4MTY1ODgiLCJjcmVhdGVkX2F0IjoiMjAyNS0wNi0yNiAxNToyNTozNS41MTA1MDAifQ.A0wy3SNHgEbdmF1IzEPlNJMNoRKewP2PEWtg_4QIuKQ"
FLEET_ID = "e696ee24-e6fb-45ce-a6bf-e225d15ca9b9"
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
DISCORD_API_BASE_URL = 'https://discord.com/api'
BUTTONS_FILE = "custom_buttons.json"
YELLOW_ROLE_ID = "59927820-d206-427d-8fd6-628fed3a298d"

# App setup
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            role = session.get("role")
            if role not in allowed_roles:
                return "Access denied", 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
# Conversion helper

def parse_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        val = value.strip().lower()
        if val == "true":
            return True
        if val == "false":
            return False
    return str(value)

@app.route("/")
def home():
    if 'user' in session:
        return redirect(url_for('station_list'))
    return render_template("start.html")

@app.route("/stations")
@require_role("coach", "headcoach", "admin")
def station_list():
    response = CollectStations(API_KEY, FLEET_ID, IncludeStations=True)
    if response.status_code == 200:
        stations = response.json().get("stations", [])

        region_filter = request.args.get("region")
        player_filter = request.args.get("player_count")
        if region_filter:
            stations = [s for s in stations if s.get("region") == region_filter]
        if player_filter:
            stations = [s for s in stations if str(s.get("player_count")) == player_filter]

        regions = sorted(set(s.get("region") for s in stations if s.get("region")))
        player_counts = sorted(set(str(s.get("player_count")) for s in stations if s.get("player_count") is not None))

        return render_template("stations.html", stations=stations, regions=regions, player_counts=player_counts)
    else:
        return f"Failed to fetch stations: {response.status_code}", 500

@app.route("/station/<station_id>")
def station_detail(station_id):
    station_name = request.args.get("station_name", "Unnamed Station")
    region = request.args.get("region", "Unknown")
    player_count = request.args.get("player_count", "N/A")

    response = ConfigReadStation(API_KEY, station_id)
    if response.status_code == 200:
        config = response.json()
        scraprun_status = config.get(
            "loadedgamemodes.scraprunprime.modulestate.dashboardconfigoverrides.bscraprunopen",
            False
        )

        buttons = load_buttons()

        return render_template(
            "station_detail.html",
            station_name=station_name,
            station_id=station_id,
            region=region,
            player_count=player_count,
            config=config,
            scraprun_enabled=scraprun_status,
            buttons=buttons
        )
    else:
        return f"Failed to fetch station config: {response.status_code}", 500

@app.route("/station/<station_id>/scraprun/<action>", methods=["POST"])
def set_scraprun(station_id, action):
    value = "true" if action == "enable" else "false"
    payload = {
        "loadedgamemodes.scraprunprime.modulestate.dashboardconfigoverrides.bscraprunopen": value
    }

    station_name = request.args.get("station_name", "Unnamed Station")
    region = request.args.get("region", "Unknown")
    player_count = request.args.get("player_count", "N/A")

    ConfigSendStation(API_KEY, station_id, payload)

    return redirect(url_for("station_detail",
                            station_id=station_id,
                            station_name=station_name,
                            region=region,
                            player_count=player_count))

@app.route('/login')
def login():
    return redirect(
        f"{DISCORD_API_BASE_URL}/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify"
    )

@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'scope': 'identify'
    }

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    token_response = requests.post(
        f"{DISCORD_API_BASE_URL}/oauth2/token",
        data=data,
        headers=headers
    )
    token_json = token_response.json()
    access_token = token_json.get('access_token')

    user_response = requests.get(
        f"{DISCORD_API_BASE_URL}/users/@me",
        headers={'Authorization': f'Bearer {access_token}'}
    )
    user_json = user_response.json()

    session['user'] = user_json
    session['discord_id'] = user_json["id"]
    session['role'] = get_user_role(user_json["id"])
    print("Logged in user ID:", user_json["id"])
    print("Assigned role:", session['role'])


    # Auto-save/refresh username
    try:
        with open("user_roles.json", "r") as f:
            roles = json.load(f)
    except:
        roles = {}

    uid = str(user_json["id"])
    if uid in roles:
        if isinstance(roles[uid], dict):
            roles[uid]["username"] = user_json["username"]
        else:
            roles[uid] = {
                "role": roles[uid],
                "username": user_json["username"]
            }

        with open("user_roles.json", "w") as f:
            json.dump(roles, f, indent=2)

    print("Logged in user ID:", user_json["id"])
    print("Assigned role:", session['role'])
    return redirect(url_for('station_list'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/admin')
@require_role("admin")
def admin_panel():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('admin.html', user=session['user'])

# Button Config

def load_buttons():
    if not os.path.exists(BUTTONS_FILE):
        return {}

    with open(BUTTONS_FILE, "r") as f:
        raw = json.load(f)

    if not raw or isinstance(list(raw.values())[0], dict):
        return raw

    upgraded = {}
    for key, label in raw.items():
        upgraded[key] = {
            "label": label,
            "enable_value": "true",
            "disable_action": "remove"
        }

    save_buttons(upgraded)
    return upgraded

def save_buttons(buttons):
    with open(BUTTONS_FILE, "w") as f:
        json.dump(buttons, f, indent=2)

@app.route('/admin/fields', methods=["GET", "POST"])
@require_role("admin")
def admin_fields():
    if 'user' not in session:
        return redirect(url_for('login'))

    buttons = load_buttons()

    if request.method == "POST":
        key = request.form.get("key")
        label = request.form.get("value")
        enable_value = request.form.get("enable_value")
        disable_value = request.form.get("disable_value")

        if key and label and enable_value is not None:
            buttons[key] = {
                "label": label,
                "enable_value": enable_value,
                "disable_value": disable_value
            }
            save_buttons(buttons)


    return render_template("admin_fields.html", user=session['user'], buttons=buttons)

@app.route('/admin/fields/delete', methods=["POST"])
def delete_button():
    if 'user' not in session:
        return redirect(url_for('login'))

    key = request.form.get("delete_key")
    buttons = load_buttons()

    if key in buttons:
        del buttons[key]
        save_buttons(buttons)

    return redirect(url_for('admin_fields'))

@app.route('/admin/fields/update', methods=["POST"])
def update_button():
    if 'user' not in session:
        return redirect(url_for('login'))

    original_key = request.form.get("original_key")
    new_key = request.form.get("key")
    new_label = request.form.get("value")
    new_enable_value = request.form.get("enable_value")
    new_disable_value = request.form.get("disable_value")

    buttons = load_buttons()

    if original_key in buttons:
        del buttons[original_key]
        buttons[new_key] = {
            "label": new_label,
            "enable_value": new_enable_value,
            "disable_value": new_disable_value
        }
        save_buttons(buttons)

    return redirect(url_for('admin_fields'))

@app.route("/station/<station_id>/custom/<path:key>/<action>", methods=["POST"])
def set_custom_config(station_id, key, action):
    if 'user' not in session:
        return redirect(url_for('login'))

    buttons = load_buttons()
    button_data = buttons.get(key, {})

    station_name = request.args.get("station_name", "Unnamed Station")
    region = request.args.get("region", "Unknown")
    player_count = request.args.get("player_count", "N/A")

    payload = {}

    if button_data.get("type") == "multi":
        for pair in button_data.get("pairs", []):
            value = pair.get("enable") if action == "enable" else pair.get("disable")
            if value is not None:
                parsed = parse_value(value)
                payload[pair["key"]] = parsed
    else:
        raw_value = button_data.get("enable_value") if action == "enable" else button_data.get("disable_value")
        if raw_value is not None:
            value = parse_value(raw_value)
            payload = build_nested_config(key, value)

    ConfigSendStation(API_KEY, station_id, payload)

    return redirect(url_for("station_detail",
                            station_id=station_id,
                            station_name=station_name,
                            region=region,
                            player_count=player_count))

def build_nested_config(flat_key, value):
    keys = flat_key.split(".")
    result = current = {}
    for part in keys[:-1]:
        current[part] = {}
        current = current[part]
    current[keys[-1]] = value
    return result

@app.route('/admin/fields/multi', methods=["POST"])
def add_multi_button():
    if 'user' not in session:
        return redirect(url_for('login'))

    label = request.form.get("label")
    keys = request.form.getlist("key[]")
    enables = request.form.getlist("enable[]")
    disables = request.form.getlist("disable[]")

    if not label or not keys:
        return redirect(url_for('admin_fields'))

    pairs = []
    for i in range(len(keys)):
        key = keys[i].strip()
        enable = enables[i].strip() if i < len(enables) else None
        disable = disables[i].strip() if i < len(disables) else None
        if key and enable:
            pairs.append({
                "key": key,
                "enable": enable,
                "disable": disable
            })

    if not pairs:
        return redirect(url_for('admin_fields'))

    # Create a unique internal key for saving (doesn't show on button)
    internal_key = f"multi_{label.lower().replace(' ', '_')}"

    buttons = load_buttons()
    buttons[internal_key] = {
        "label": label,
        "type": "multi",
        "pairs": pairs
    }
    save_buttons(buttons)

    return redirect(url_for('admin_fields'))

@app.route('/admin/fields/multi/update', methods=["POST"])
def update_multi_button():
    if 'user' not in session:
        return redirect(url_for('login'))

    original_key = request.form.get("original_key")
    label = request.form.get("label")
    keys = request.form.getlist("key[]")
    enables = request.form.getlist("enable[]")
    disables = request.form.getlist("disable[]")

    if not original_key or not label:
        return redirect(url_for('admin_fields'))

    pairs = []
    for i in range(len(keys)):
        key = keys[i].strip()
        enable = enables[i].strip()
        disable = disables[i].strip() if i < len(disables) else None
        if key and enable:
            pairs.append({
                "key": key,
                "enable": enable,
                "disable": disable
            })

    buttons = load_buttons()
    buttons[original_key] = {
        "label": label,
        "type": "multi",
        "pairs": pairs
    }
    save_buttons(buttons)

    return redirect(url_for('admin_fields'))

def merge_dicts(a, b):
    for key in b:
        if key in a and isinstance(a[key], dict) and isinstance(b[key], dict):
            merge_dicts(a[key], b[key])
        else:
            a[key] = b[key]
    return a

def get_user_role(discord_id):
    try:
        with open("user_roles.json") as f:
            data = json.load(f)

        entry = data.get(str(discord_id))

        # Handle both formats
        if isinstance(entry, dict):
            return entry.get("role")
        elif isinstance(entry, str):
            return entry  # legacy format
        else:
            return None
    except Exception as e:
        print("get_user_role error:", e)
        return None

@app.route('/admin/roles', methods=["GET", "POST"])
@require_role("admin")
def manage_roles():
    roles_file = "user_roles.json"

    if request.method == "POST":
        discord_id = request.form.get("discord_id", "").strip()
        role = request.form.get("role", "").strip().lower()

        if discord_id and role:
            try:
                with open(roles_file, "r") as f:
                    data = json.load(f)
            except:
                data = {}

            data[discord_id] = {
                "role": role,
                "username": session['user']['username'] if 'user' in session else "Unknown"
            }

            with open(roles_file, "w") as f:
                json.dump(data, f, indent=2)

            flash("Role updated for user!", "success")
            return redirect(url_for("manage_roles"))

    # Show existing roles
    try:
        with open(roles_file) as f:
            user_roles = json.load(f)
    except:
        user_roles = {}

    # Build user display mapping
    user_display = {}
    for uid in user_roles:
        entry = user_roles[uid]
        if isinstance(entry, dict) and "username" in entry:
            user_display[uid] = entry["username"]
        else:
            user_display[uid] = "Unknown"

    return render_template("admin_roles.html", user_roles=user_roles, user_display=user_display)




@app.route('/admin/roles/delete', methods=["POST"])
@require_role("admin")
def delete_role():
    discord_id = request.form.get("discord_id")

    try:
        with open("user_roles.json", "r") as f:
            data = json.load(f)
    except:
        data = {}

    if discord_id in data:
        del data[discord_id]
        with open("user_roles.json", "w") as f:
            json.dump(data, f, indent=2)

    return redirect(url_for('manage_roles'))


@app.route('/admin/roles/update', methods=["POST"])
@require_role("admin")
def update_role():
    discord_id = request.form.get("discord_id")
    new_role = request.form.get("role")

    if not discord_id or not new_role:
        return redirect(url_for('manage_roles'))

    try:
        with open("user_roles.json", "r") as f:
            data = json.load(f)
    except:
        data = {}

    # Keep existing username if available
    if discord_id in data and isinstance(data[discord_id], dict):
        username = data[discord_id].get("username", "Unknown")
    else:
        username = "Unknown"

    data[discord_id] = {
        "role": new_role,
        "username": username
    }

    with open("user_roles.json", "w") as f:
        json.dump(data, f, indent=2)

    flash("Role updated!", "success")
    return redirect(url_for('manage_roles'))

@app.route('/admin/personal', methods=["GET", "POST"])
@require_role("headcoach", "admin")
def personal_settings():
    user_id = str(session.get("discord_id"))

    try:
        with open("user_roles.json", "r") as f:
            roles = json.load(f)
    except:
        roles = {}

    user_entry = roles.get(user_id, {})
    metaname = user_entry.get("metaname", "Unknown")
    yellow_name_enabled = user_entry.get("yellow_name", False)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "enable":
            roles[user_id]["yellow_name"] = True
        elif action == "disable":
            roles[user_id]["yellow_name"] = False

        with open("user_roles.json", "w") as f:
            json.dump(roles, f, indent=2)

        return redirect(url_for("personal_settings"))

    return render_template(
        "personal.html",
        metaname=metaname,
        yellow_name_enabled=yellow_name_enabled
    )

@app.route("/admin/personal/toggle_yellow_name", methods=["POST"])
@require_role("headcoach", "admin")
def toggle_yellow_name():
    user_id = str(session.get("discord_id"))
    action = request.form.get("action")

    try:
        with open("user_roles.json", "r") as f:
            data = json.load(f)
    except:
        data = {}

    if user_id not in data:
        return redirect(url_for("personal_settings"))

    if isinstance(data[user_id], dict):
        player_id = data[user_id].get("player_id")
        if action == "enable":
            data[user_id]["yellow_name"] = True
            if player_id:
                give_yellow_role(player_id)
        elif action == "disable":
            data[user_id]["yellow_name"] = False
            if player_id:
                remove_yellow_role(player_id)

    with open("user_roles.json", "w") as f:
        json.dump(data, f, indent=2)

    return redirect(url_for("personal_settings"))

from A2ApiLib import UpdateUserRole

YELLOW_ROLE_ID = "59927820-d206-427d-8fd6-628fed3a298d"

def give_yellow_role(player_id):
    result = UpdateUserRole(API_KEY, FLEET_ID, player_id, YELLOW_ROLE_ID, Give=True)
    print(f"🟡 Gave Yellow Role: {result}")
    return result

def remove_yellow_role(player_id):
    result = UpdateUserRole(API_KEY, FLEET_ID, player_id, YELLOW_ROLE_ID, Give=False)
    print(f"🟡 Removed Yellow Role: {result}")
    return result

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

