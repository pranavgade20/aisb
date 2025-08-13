from flask import Flask, render_template, jsonify, request, send_file, session
import pickle
import os
import json
import random
from datetime import datetime
import threading
import time
import re

app = Flask(__name__)
app.secret_key = "snake_game_secret_key_2024"

# Paths anchored to this file's directory for consistent behavior
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Game state storage
leaderboard_file = os.path.join(BASE_DIR, "leaderboard.json")
game_states_dir = os.path.join(BASE_DIR, "game_states")
valid_md5_file = os.path.join(BASE_DIR, "valid_md5.txt")

# Ensure directories exist
os.makedirs(game_states_dir, exist_ok=True)

# Initialize leaderboard if it doesn't exist
if not os.path.exists(leaderboard_file):
    with open(leaderboard_file, "w") as f:
        json.dump([], f)


def load_leaderboard():
    try:
        with open(leaderboard_file, "r") as f:
            return json.load(f)
    except:
        return []


def save_leaderboard(leaderboard):
    with open(leaderboard_file, "w") as f:
        json.dump(leaderboard, f, indent=2)


def load_valid_hashes() -> set:
    """Load the set of valid MD5 hashes recorded at download time."""
    if not os.path.exists(valid_md5_file):
        return set()
    with open(valid_md5_file, "r") as f:
        return {line.strip() for line in f if line.strip()}


def append_valid_hash(md5_hex: str) -> None:
    """Append a new valid MD5 hash to the allow-list file."""
    with open(valid_md5_file, "a") as f:
        f.write(md5_hex + "\n")


def is_valid_player_name(player_name: str) -> bool:
    """Allow any printable characters except control chars. Limit length."""
    if not isinstance(player_name, str):
        return False
    if len(player_name) == 0 or len(player_name) > 128:
        return False
    # Disallow ASCII control characters (0x00-0x1F, 0x7F)
    return re.fullmatch(r"[^\x00-\x1F\x7F]+", player_name) is not None


def validate_game_state_upload(state: dict):
    """Validate structure and bounds of an uploaded game state.
    Returns (True, None) if valid, else (False, error_message).
    """
    required_keys = ["apple_pos", "apple_size", "snakes", "player_name"]
    if not isinstance(state, dict):
        return False, "State must be a JSON object"
    if not all(key in state for key in required_keys):
        return False, "Missing required keys"

    # apple_pos validation
    apple_pos = state.get("apple_pos")
    if (
        not isinstance(apple_pos, list)
        or len(apple_pos) != 2
        or not all(isinstance(v, int) for v in apple_pos)
        or not (0 <= apple_pos[0] <= 19)
        or not (0 <= apple_pos[1] <= 19)
    ):
        return False, "Invalid apple_pos"

    # apple_size validation
    apple_size = state.get("apple_size")
    if not isinstance(apple_size, int) or not (1 <= apple_size <= 1_000_000):
        return False, "Invalid apple_size"

    # snakes validation
    snakes = state.get("snakes")
    if not isinstance(snakes, list) or len(snakes) > 200:
        return False, "Invalid snakes list"
    for s in snakes:
        if (
            not isinstance(s, list)
            or len(s) != 2
            or not all(isinstance(v, int) for v in s)
            or not (0 <= s[0] <= 19)
            or not (0 <= s[1] <= 19)
        ):
            return False, "Invalid snake position"

    # player_name validation
    player_name = state.get("player_name")
    if not is_valid_player_name(player_name):
        return False, "Invalid player_name"

    return True, None


def generate_game_state(apple_size=1):
    """Generate a new game state"""
    return {
        "apple_pos": [random.randint(1, 18), random.randint(1, 18)],
        "apple_size": apple_size,
        "snakes": [[random.randint(0, 19), random.randint(0, 19)] for _ in range(5)],
        "player_name": session.get("player_name", "Anonymous"),
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/")
def index():
    if "player_name" not in session:
        session["player_name"] = f"Player{random.randint(1000, 9999)}"

    leaderboard = load_leaderboard()
    # Sort by score (apple_size) descending
    leaderboard.sort(key=lambda x: x.get("apple_size", 0), reverse=True)

    return render_template("index.html", player_name=session["player_name"], leaderboard=leaderboard[:10])


@app.route("/api/game_state")
def get_game_state():
    """Get current game state"""
    if "game_state" not in session:
        session["game_state"] = generate_game_state()

    return jsonify(session["game_state"])


@app.route("/api/update_game", methods=["POST"])
def update_game():
    """Update game state (move apple, eat snake, etc.)"""
    data = request.get_json()

    if "game_state" not in session:
        session["game_state"] = generate_game_state()

    game_state = session["game_state"]

    # Update apple position
    if "apple_pos" in data:
        game_state["apple_pos"] = data["apple_pos"]

    # Optional full-state sync from client
    if "apple_size" in data:
        game_state["apple_size"] = int(data["apple_size"])
    if "snakes" in data and isinstance(data["snakes"], list):
        game_state["snakes"] = data["snakes"]

    # Handle snake eating
    if data.get("ate_snake", False):
        game_state["apple_size"] += 1
        # Remove eaten snake and add new one
        if game_state["snakes"]:
            game_state["snakes"].pop(0)
        game_state["snakes"].append([random.randint(0, 19), random.randint(0, 19)])

    # Handle game over
    if data.get("game_over", False):
        # Save to leaderboard
        leaderboard = load_leaderboard()
        leaderboard.append(
            {
                "player_name": game_state["player_name"],
                "apple_size": game_state["apple_size"],
                "timestamp": datetime.now().isoformat(),
            }
        )
        save_leaderboard(leaderboard)

        # Reset game state
        session["game_state"] = generate_game_state()

    session["game_state"] = game_state
    return jsonify({"success": True})


@app.route("/api/download_state")
def download_state():
    """Download current game state as pickle file"""
    if "game_state" not in session:
        session["game_state"] = generate_game_state()

    game_state = session["game_state"]

    # Create pickle file
    safe_name = safe_filename_component(game_state["player_name"])
    filename = f"game_state_{safe_name}_{int(time.time())}.pkl"
    filepath = os.path.join(game_states_dir, filename)

    with open(filepath, "wb") as f:
        pickle.dump(game_state, f)

    # Add hasing here, calc and add to db
    # save to file the hash(game_state['player_name']_game_state['apple_size'])
    current_hash = calc_game_state_hash(game_state)

    # added it to db, it's not leaderboardb becaue they may be results that are in a middle of a game
    append_valid_hash(current_hash)

    return send_file(filepath, as_attachment=True, download_name=filename)


def calc_game_state_hash(game_state):
    import hashlib

    # Ensure both components are bytes before concatenation
    player_name = game_state["player_name"].strip()
    apple_size = game_state["apple_size"]
    # If player_name is already bytes, don't encode again
    if isinstance(player_name, bytes):
        f = player_name
    else:
        f = str(player_name).encode()
    # apple_size is always int, so this is safe
    e = ("_" + str(apple_size)).encode()

    return hashlib.md5(f + e).hexdigest()


def safe_filename_component(name: str) -> str:
    """Encode an arbitrary string into a filesystem-safe ASCII token."""
    import base64

    encoded = base64.urlsafe_b64encode(name.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


@app.route("/api/upload_state", methods=["POST"])
def upload_state():
    """Upload and load game state from pickle file"""
    print("=== UPLOAD STATE CALLED ===")

    if "file" not in request.files:
        print("No file in request.files")
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    print(f"File received: {file.filename}")

    if file.filename == "":
        print("Empty filename")
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.endswith(".pkl"):
        print("Not a pickle file")
        return jsonify({"error": "File must be a pickle file"}), 400

    try:
        # Load pickle file safely from bytes
        file.stream.seek(0)
        file_bytes = file.read()
        if not file_bytes:
            return jsonify({"error": "Uploaded file is empty"}), 400
        # Quick guard: common case where an HTML error page gets uploaded
        if file_bytes.lstrip().startswith(b"<"):
            return jsonify(
                {
                    "error": "Uploaded file looks like HTML/text, not a pickle. Please upload the .pkl downloaded from this app."
                }
            ), 400

        game_state = pickle.loads(file_bytes)
        print(f"Pickle loaded successfully: {game_state}")

        # Basic structural validation to avoid crashes later
        required_keys = ["apple_pos", "apple_size", "snakes", "player_name"]
        if not isinstance(game_state, dict) or not all(k in game_state for k in required_keys):
            return jsonify({"error": "Invalid game state format"}), 400

        current_hash = calc_game_state_hash(game_state)

        # Check the uploaded state's hash against the allow-list captured at download time
        valid_hashes = load_valid_hashes()
        if current_hash not in valid_hashes:
            return jsonify({"error": "File must have valid hash"}), 400

        # Update session
        session["game_state"] = game_state
        session["player_name"] = game_state["player_name"]
        print(f"Session updated. New game_state: {session['game_state']}")

        return jsonify({"success": True, "game_state": game_state})

    except Exception as e:
        print(f"Exception during upload: {str(e)}")
        return jsonify({"error": f"Failed to load game state: {str(e)}"}), 400


@app.route("/api/leaderboard")
def get_leaderboard():
    """Get current leaderboard"""
    leaderboard = load_leaderboard()
    leaderboard.sort(key=lambda x: x.get("apple_size", 0), reverse=True)
    return jsonify(leaderboard[:10])


@app.route("/api/set_player_name", methods=["POST"])
def set_player_name():
    """Set player name"""
    data = request.get_json()
    player_name = data.get("player_name", "").strip()

    if not is_valid_player_name(player_name):
        return jsonify({"error": "Invalid player name"}), 400

    session["player_name"] = player_name

    # Update current game state if it exists
    if "game_state" in session:
        session["game_state"]["player_name"] = player_name

    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
