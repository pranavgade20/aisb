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
app.secret_key = 'snake_game_secret_key_2024'

# Game state storage
leaderboard_file = 'leaderboard.json'
game_states_dir = 'game_states'

# Ensure directories exist
os.makedirs(game_states_dir, exist_ok=True)

# Initialize leaderboard if it doesn't exist
if not os.path.exists(leaderboard_file):
    with open(leaderboard_file, 'w') as f:
        json.dump([], f)

def load_leaderboard():
    try:
        with open(leaderboard_file, 'r') as f:
            return json.load(f)
    except:
        return []

def save_leaderboard(leaderboard):
    with open(leaderboard_file, 'w') as f:
        json.dump(leaderboard, f, indent=2)

def is_valid_player_name(player_name: str) -> bool:
    if not isinstance(player_name, str):
        return False
    if len(player_name) == 0 or len(player_name) > 32:
        return False
    # Allow letters, numbers, spaces, underscore, hyphen
    return re.fullmatch(r"[A-Za-z0-9 _-]+", player_name) is not None

def validate_game_state_upload(state: dict):
    """Validate structure and bounds of an uploaded game state.
    Returns (True, None) if valid, else (False, error_message).
    """
    required_keys = ['apple_pos', 'apple_size', 'snakes', 'player_name']
    if not isinstance(state, dict):
        return False, 'State must be a JSON object'
    if not all(key in state for key in required_keys):
        return False, 'Missing required keys'

    # apple_pos validation
    apple_pos = state.get('apple_pos')
    if (not isinstance(apple_pos, list) or len(apple_pos) != 2 or
        not all(isinstance(v, int) for v in apple_pos) or
        not (0 <= apple_pos[0] <= 19) or not (0 <= apple_pos[1] <= 19)):
        return False, 'Invalid apple_pos'

    # apple_size validation
    apple_size = state.get('apple_size')
    if not isinstance(apple_size, int) or not (1 <= apple_size <= 1_000_000):
        return False, 'Invalid apple_size'

    # snakes validation
    snakes = state.get('snakes')
    if not isinstance(snakes, list) or len(snakes) > 200:
        return False, 'Invalid snakes list'
    for s in snakes:
        if (not isinstance(s, list) or len(s) != 2 or
            not all(isinstance(v, int) for v in s) or
            not (0 <= s[0] <= 19) or not (0 <= s[1] <= 19)):
            return False, 'Invalid snake position'

    # player_name validation
    player_name = state.get('player_name')
    if not is_valid_player_name(player_name):
        return False, 'Invalid player_name'

    return True, None

def generate_game_state(apple_size=1):
    """Generate a new game state"""
    return {
        'apple_pos': [random.randint(1, 18), random.randint(1, 18)],
        'apple_size': apple_size,
        'snakes': [[random.randint(0, 19), random.randint(0, 19)] for _ in range(5)],
        'player_name': session.get('player_name', 'Anonymous'),
        'timestamp': datetime.now().isoformat()
    }

@app.route('/')
def index():
    if 'player_name' not in session:
        session['player_name'] = f"Player{random.randint(1000, 9999)}"
    
    leaderboard = load_leaderboard()
    # Sort by score (apple_size) descending
    leaderboard.sort(key=lambda x: x.get('apple_size', 0), reverse=True)
    
    return render_template('index.html', 
                         player_name=session['player_name'],
                         leaderboard=leaderboard[:10])

@app.route('/api/game_state')
def get_game_state():
    """Get current game state"""
    if 'game_state' not in session:
        session['game_state'] = generate_game_state()
    
    return jsonify(session['game_state'])

@app.route('/api/update_game', methods=['POST'])
def update_game():
    """Update game state (move apple, eat snake, etc.)"""
    data = request.get_json()
    
    if 'game_state' not in session:
        session['game_state'] = generate_game_state()
    
    game_state = session['game_state']
    
    # Update apple position
    if 'apple_pos' in data:
        game_state['apple_pos'] = data['apple_pos']
    
    # Optional full-state sync from client
    if 'apple_size' in data:
        game_state['apple_size'] = int(data['apple_size'])
    if 'snakes' in data and isinstance(data['snakes'], list):
        game_state['snakes'] = data['snakes']
    
    # Handle snake eating
    if data.get('ate_snake', False):
        game_state['apple_size'] += 1
        # Remove eaten snake and add new one
        if game_state['snakes']:
            game_state['snakes'].pop(0)
        game_state['snakes'].append([random.randint(0, 19), random.randint(0, 19)])
    
    # Handle game over
    if data.get('game_over', False):
        # Save to leaderboard
        leaderboard = load_leaderboard()
        leaderboard.append({
            'player_name': game_state['player_name'],
            'apple_size': game_state['apple_size'],
            'timestamp': datetime.now().isoformat()
        })
        save_leaderboard(leaderboard)
        
        # Reset game state
        session['game_state'] = generate_game_state()
    
    session['game_state'] = game_state
    return jsonify({'success': True})

@app.route('/api/download_state')
def download_state():
    """Download current game state as pickle file"""
    if 'game_state' not in session:
        session['game_state'] = generate_game_state()
    
    game_state = session['game_state']
    
    # Create pickle file
    filename = f"game_state_{game_state['player_name']}_{int(time.time())}.pkl"
    filepath = os.path.join(game_states_dir, filename)
    
    with open(filepath, 'wb') as f:
        pickle.dump(game_state, f)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/api/upload_state', methods=['POST'])
def upload_state():
    """Upload and load game state from pickle file"""
    print("=== UPLOAD STATE CALLED ===")
    
    if 'file' not in request.files:
        print("No file in request.files")
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    print(f"File received: {file.filename}")
    
    if file.filename == '':
        print("Empty filename")
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.pkl'):
        print("Not a pickle file")
        return jsonify({'error': 'File must be a pickle file'}), 400
    
    try:
        # Load pickle file
        game_state = pickle.load(file)
        print(f"Pickle loaded successfully: {game_state}")
        
        # Basic structural validation to avoid crashes later
        required_keys = ['apple_pos', 'apple_size', 'snakes', 'player_name']
        if not isinstance(game_state, dict) or not all(k in game_state for k in required_keys):
            return jsonify({'error': 'Invalid game state format'}), 400
        
        # Update session
        session['game_state'] = game_state
        session['player_name'] = game_state['player_name']
        print(f"Session updated. New game_state: {session['game_state']}")
        
        return jsonify({'success': True, 'game_state': game_state})
    
    except Exception as e:
        print(f"Exception during upload: {str(e)}")
        return jsonify({'error': f'Failed to load game state: {str(e)}'}), 400

@app.route('/api/leaderboard')
def get_leaderboard():
    """Get current leaderboard"""
    leaderboard = load_leaderboard()
    leaderboard.sort(key=lambda x: x.get('apple_size', 0), reverse=True)
    return jsonify(leaderboard[:10])

@app.route('/api/set_player_name', methods=['POST'])
def set_player_name():
    """Set player name"""
    data = request.get_json()
    player_name = data.get('player_name', '').strip()
    
    if not player_name:
        return jsonify({'error': 'Player name cannot be empty'}), 400
    
    session['player_name'] = player_name
    
    # Update current game state if it exists
    if 'game_state' in session:
        session['game_state']['player_name'] = player_name
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
