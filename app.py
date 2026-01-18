from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import os
import requests

app = Flask(__name__)

# Your bot API
BOT_API_BASE_URL = "https://your-bot-project-name.up.railway.app"
BOT_API_PORT = "30151"

# ---------- LOGIN FIRST ----------
@app.route('/')
def home():
    return redirect(url_for('login_page'))   # OPEN LOGIN FIRST

@app.route('/login')
def login_page():
    return render_template("login.html")     # SHOW LOGIN.HTML

# When user clicks login → go to index page
@app.route('/do_login', methods=['POST'])
def do_login():
    # You can add password check here later
    return redirect(url_for('index_page'))

# ---------- MAIN PAGE ----------
@app.route('/index')
def index_page():
    try:
        with open('emotes.json', 'r') as f:
            emotes = json.load(f)
        return render_template('index.html', emotes=emotes)
    except Exception as e:
        return f"An error occurred: {e}", 500

# ---------- SEND EMOTE ----------
@app.route('/send_emote', methods=['POST'])
def send_emote():
    try:
        data = request.get_json()
        team_code = data.get('team_code')
        emote_id = data.get('emote_id')
        uids = data.get('uids', [])

        if not all([team_code, emote_id, uids]):
            return jsonify({'message': 'Error: Missing data'}), 400

        params = {
            'emote_id': emote_id,
            'tc': team_code
        }
        for i, uid in enumerate(uids):
            params[f'uid{i+1}'] = uid

        api_url = f"{BOT_API_BASE_URL}:{BOT_API_PORT}/join"
        response = requests.get(api_url, params=params, timeout=30)
        response.raise_for_status()

        return jsonify({
            'message': 'Emote request sent successfully to the bot!',
            'api_response': response.json()
        })

    except requests.exceptions.RequestException as e:
        return jsonify({'message': f'Error communicating with the bot API: {e}'}), 500

    except Exception as e:
        return jsonify({'message': f'Internal error: {e}'}), 500


if __name__ == "__main__":
    app.run(debug=True)
