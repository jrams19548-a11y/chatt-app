from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import json
from flask import Response
import time
from jinja2 import Undefined
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import ast
from datetime import datetime, timezone
import pytz
cst_timezone = pytz.timezone('America/Chicago')
class ProfanityFilter:
    def __init__(self, wordlist_file='profanity_words.txt'):
        self.profane_words = set()
        self.load_words(wordlist_file)
        
    def load_words(self, wordlist_file):
        try:
            with open(wordlist_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        self.profane_words.add(line.strip().lower())
            print(f"Loaded {len(self.profane_words)} profane words from {wordlist_file}")
        except FileNotFoundError:
            print(f"Warning: Profanity wordlist file '{wordlist_file}' not found")
            with open(wordlist_file, 'w') as f:
                f.write("# List of profane words to filter\n# One word per line\n")
    
    def _get_replacement(self, word):
        return '*' * len(word)
    
    def censor_text(self, text):
        if not text:
            return text
        censored_text = text
        for word in self.profane_words:
            pattern = r'\b' + re.escape(word) + r'\b'
            replacement = self._get_replacement(word)
            censored_text = re.sub(pattern, replacement, censored_text, flags=re.IGNORECASE)
        return censored_text

profanity_filter = ProfanityFilter(wordlist_file='profanity_words.txt')

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def load_users():
    users = {}
    try:
        with open('users.txt', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.strip().split('|')
                username, password, display_name, role = parts[:4]
                is_suspended = parts[4] if len(parts) > 4 else "false"
                is_muted = parts[5] if len(parts) > 5 else "false"
                profile_pic = parts[6] if len(parts) > 6 else ""
                users[username] = {
                    'password': password,
                    'display_name': display_name,
                    'role': role,
                    'profile_pic': profile_pic,
                    'is_suspended': is_suspended == "true",
                    'is_muted': is_muted == "true"
                }
    except FileNotFoundError:
        pass
    return users

def save_users():
    with open('users.txt', 'w') as f:
        f.write('# Format: username|password_hash|display_name|role|is_suspended|is_muted|bio|profile_pic\n')
        for username, data in users.items():
            f.write(f"{username}|{data['password']}|{data['display_name']}|{data['role']}|{str(data.get('is_suspended', False)).lower()}|{str(data.get('is_muted', False)).lower()}|{data.get('bio', '')}|{data.get('profile_pic', '')}\n")

@app.route('/profile/<username>')
@login_required
def view_profile(username):
    if username not in users:
        flash('User not found')
        return redirect(url_for('home'))
    bios = load_bios()
    user_data = users[username].copy()
    user_data['bio'] = bios.get(username, 'No bio provided.')
    friends, _ = load_friends()
    user_friends = friends.get(current_user.id, [])
    return render_template('profile.html', username=username, user_data=user_data, 
                         friends=user_friends, active_users=active_users, users=users)

def load_bios():
    bios = {}
    try:
        with open('bios.txt', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                username, bio = line.strip().split('|', 1)
                bios[username] = bio
    except FileNotFoundError:
        pass
    return bios

def save_bios(bios):
    with open('bios.txt', 'w') as f:
        f.write('# Format: username|bio\n')
        for username, bio in bios.items():
            f.write(f"{username}|{bio}\n")

@app.route('/update_bio', methods=['POST'])
@login_required
def update_bio():
    bio = request.form.get('bio', '').strip()
    # Apply profanity filter to bios
    filtered_bio = profanity_filter.censor_text(bio)
    bios = load_bios()
    bios[current_user.id] = filtered_bio
    save_bios(bios)
    flash('Bio updated successfully!', 'success')
    return redirect(url_for('home'))

users = load_users()
messages = []
ROLES = ['Owner', 'Admin', 'Mod', 'Regular User', 'Co-owner', 'Developer']

def get_dm_filename(user1, user2):
    # Sort usernames to ensure consistent filename regardless of sender/recipient
    users = sorted([user1, user2])
    return f"dm_{users[0]}_{users[1]}.txt"

def load_dm_history(user1, user2):
    filepath = get_dm_filename(user1, user2)
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r') as f:
            messages = []
            for line in f:
                if line.strip():
                    try:
                        messages.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        try:
                            messages.append(ast.literal_eval(line.strip()))
                        except:
                            pass
            return messages
    except Exception as e:
        print(f"Error loading DM history from {filepath}: {e}")
        return []

def save_dm_history(user1, user2, messages):
    filepath = get_dm_filename(user1, user2)
    try:
        with open(filepath, 'w') as f:
            for msg in messages:
                f.write(json.dumps(msg) + "\n")
    except Exception as e:
        print(f"Error saving DM history to {filepath}: {e}")


def load_chat_history():
    chat_rooms = {
        'general': [],
        'random': [],
        'support': [],
        'admin' : []     
    }
    for room in chat_rooms.keys():
        try:
            with open(f'chat_{room}.txt', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            msg = json.loads(line.strip())
                        except json.JSONDecodeError:
                            try:
                                msg = ast.literal_eval(line.strip())
                            except:
                                continue
                        chat_rooms[room].append(msg)
        except FileNotFoundError:
            pass
    return chat_rooms

def save_chat_history(room):
    with open(f'chat_{room}.txt', 'w') as f:
        for msg in chat_rooms[room]:
            f.write(json.dumps(msg) + "\n")

def load_announcements():
    try:
        with open('announcements.txt', 'r') as f:
            announcements_list = []
            for line in f:
                if line.strip():
                    try:
                        announcements_list.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        try:
                            announcements_list.append(ast.literal_eval(line.strip()))
                        except:
                            continue
            return announcements_list
    except FileNotFoundError:
        return []

def save_announcements():
    with open('announcements.txt', 'w') as f:
        for announcement in announcements:
            f.write(json.dumps(announcement) + "\n")

chat_rooms = load_chat_history()
announcements = load_announcements()
active_users = {
    'general': set(),
    'random': set(),
    'support': set(),
    'admin': set()
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.display_name = users[username]['display_name']
        self.role = users[username]['role']

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        display_name = request.form.get('display_name', username)

        if username in users:
            flash('Username already exists')
            return redirect(url_for('register'))

        users[username] = {
            'password': generate_password_hash(password),
            'display_name': display_name,
            'role': 'Regular User'
        }
        save_users()
        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username]['password'], password):
            login_user(User(username))
            return redirect(url_for('home'))

        flash('Invalid username or password')

    return render_template('login.html')

@app.route('/settings', methods=['POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        response = {'status': 'error', 'message': 'Unknown error occurred'}

        if action == 'password':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            if not check_password_hash(users[current_user.id]['password'], current_password):
                response['message'] = 'Current password is incorrect'
            elif new_password != confirm_password:
                response['message'] = 'New passwords do not match'
            else:
                users[current_user.id]['password'] = generate_password_hash(new_password)
                save_users()
                response = {'status': 'success', 'message': 'Password updated successfully!'}

        elif action == 'profile':
            new_username = request.form['new_username']
            new_display_name = request.form['new_display_name']

            if new_username != current_user.id and new_username in users:
                response['message'] = 'Username already exists'
            else:
                profile_pic = request.form.get('profile_pic', '')
                if new_username != current_user.id:
                    users[new_username] = users.pop(current_user.id)
                    logout_user()
                    login_user(User(new_username))
                users[current_user.id]['display_name'] = new_display_name
                users[current_user.id]['profile_pic'] = profile_pic
                save_users()
                response = {'status': 'success', 'message': 'Profile updated successfully!'}

        return jsonify(response)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/channel/<room>')
@login_required
def channel(room):
    if room not in chat_rooms:
        return redirect(url_for('home'))

    # If the room is 'admin', enforce role
    if room.lower() == 'admin' and current_user.role not in 'Admin':
        flash('You do not have permission to access the admin channel.')
        return redirect(url_for('home'))
        # Alternatively: abort(403)

    return render_template('channel.html', room=room, rooms=chat_rooms.keys(), users=users)


def requires_role(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                flash('You do not have permission to access this feature.')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/user/<username>', methods=['POST'])
@login_required
@requires_role(['Owner', 'Admin', 'Mod'])
def manage_user(username):
    if username not in users:
        flash('User not found')
        return redirect(url_for('settings'))

    if username == "CreeperCast5008":
        flash('No U')
        return redirect(url_for('/'))

    action = request.form.get('action')
    if action == 'role' and current_user.role in ['Owner', 'Admin']:
        new_role = request.form.get('role')
        if new_role in ROLES:
            users[username]['role'] = new_role
            save_users()
            flash('User role updated successfully!')
    elif action == 'suspend':
        users[username]['is_suspended'] = not users[username].get('is_suspended', False)
        save_users()
        flash(f'User {"suspended" if users[username]["is_suspended"] else "unsuspended"} successfully!')
    elif action == 'mute':
        users[username]['is_muted'] = not users[username].get('is_muted', False)
        save_users()
        flash(f'User {"muted" if users[username]["is_muted"] else "unmuted"} successfully!')

    return redirect(url_for('home'))

@app.before_request
def check_user_status():
    if current_user.is_authenticated:
        if users[current_user.id].get('is_suspended', False):
            logout_user()
            flash('Your account has been suspended')
            return redirect(url_for('login'))

# Define some basic emojis
EMOJIS = {
    'smile': '😊',
    'laugh': '😂',
    'heart': '❤️',
    'thumbsup': '👍',
    'wink': '😉',
    'fire': '🔥',
    'tada': '🎉',
    'rocket': '🚀',
    'star': '⭐',
    'check': '✅'
}

def parse_message(text):
    # First, apply profanity filter
    text = profanity_filter.censor_text(text)
    # Replace emoji codes
    for code, emoji in EMOJIS.items():
        text = text.replace(f':{code}:', emoji)

    # Format text while preserving links and handling mentions
    words = text.split()
    formatted = []
    for word in words:
        if word.startswith(('http://', 'https://')):
            formatted.append(word)
        elif word.startswith('@'):
            username = word[1:]
            if username in users:
                formatted.append(f'<a href="/profile/{username}" class="mention">@{users[username]["display_name"]}</a>')
            else:
                formatted.append(word)
        else:
            formatted.append(word)
    return ' '.join(formatted)

def handle_command(message, room):
    parts = message.split()
    command = parts[0].lower()

    if current_user.role not in ['Owner', 'Developer', 'Admin']:
        return None

    if command == '/ban' and len(parts) > 1:
        target = parts[1]
        if target in users:
            users[target]['is_suspended'] = True
            save_users()
            return {'text': f'User {target} has been banned', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}

    elif command == '/unban' and len(parts) > 1:
        target = parts[1]
        if target in users:
            users[target]['is_suspended'] = False
            save_users()
            return {'text': f'User {target} has been unbanned', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}

    elif command == '/chatclear':
        chat_rooms[room].clear()
        save_chat_history(room)
        return {'text': 'Chat has been cleared', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}

    elif command == '/role' and len(parts) > 2:
        target = parts[1]
        new_role = ' '.join(parts[2:])
        if target in users and new_role in ROLES:
            users[target]['role'] = new_role
            save_users()
            return {'text': f'Changed {target}\'s role to {new_role}', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}
    elif command == '/help':
        return {'text': 
        '/ban {username}-bans someone /unban {username}-unbans someone  /chatclear-clears the chat history  /role {username} {role}-gives a user a specified role /mute {username}-mutes someone',
'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}
    
    if command == '/mute' and len(parts) > 1:
        target = parts[1]
        if target in users:
            users[target]['is_muted'] = True
            save_users()
            return {'text': f'User {target} has been muted', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}
    
    if command == '/unmute' and len(parts) > 1:
        target = parts[1]
        if target in users:
            users[target]['is_muted'] = False
            save_users()
            return {'text': f'User {target} has been unmuted', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}
    
        if command == '/announce' and len(parts) > 1:
            announcement_text = ' '.join(parts[1:])
            return {'text': f'{announcement_text}', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}

    else:
    # No valid command matched - return an error message
        return {'text': f'Unknown command: {command}. Type /help for a list of commands.', 'sender': 'Server', 'timestamp': datetime.now().strftime('%H:%M'), 'room': room}


@app.route('/send', methods=['POST'])
@login_required
def send():
    if users[current_user.id].get('is_muted', False):
        return jsonify({'error': 'You are currently muted'}), 403

    message = request.json.get('message')
    room = request.json.get('room', 'general')
    image_data = request.json.get('image')

    if message and message.startswith('/'):
        command_response = handle_command(message, room)
        if command_response:
            chat_rooms[room].append({
                'id': len(chat_rooms[room]),
                **command_response
            })
            save_chat_history(room)
            return jsonify([command_response])

    if (message or image_data) and room in chat_rooms:
        if message:
            message = parse_message(message)

        new_message = {
            'id': len(chat_rooms[room]),
            'text': message if message else '',
            'image': image_data,
            'timestamp': datetime.now(cst_timezone).strftime('%Y-%m-%d %I:%M %p'),
            'sender': current_user.id,
            'room': room,
            'edited': False
        }
        chat_rooms[room].append(new_message)
        save_chat_history(room)
        return jsonify([new_message])
    return jsonify([])

@app.route('/messages/<room>')
@login_required
def get_messages(room):
    if room in chat_rooms:
        # Add user to room
        active_users[room].add(current_user.id)
        return jsonify({
            'messages': chat_rooms[room],
            'users': list(active_users[room])
        })
    return jsonify({'messages': [], 'users': []})

@app.route('/leave/<room>')
@login_required
def leave_room(room):
    if room in active_users:
        active_users[room].discard(current_user.id)
    return jsonify({'success': True})

@app.route('/edit_message/<room>/<int:message_id>', methods=['POST'])
@login_required
def edit_message(room, message_id):
    if room not in chat_rooms:
        return jsonify({'error': 'Room not found'}), 404

    new_text = request.json.get('text')
    if not new_text:
        return jsonify({'error': 'No text provided'}), 400

    for msg in chat_rooms[room]:
        if msg['id'] == message_id:
            if msg['sender'] != current_user.id and current_user.role not in ['Owner', 'Admin']:
                return jsonify({'error': 'Permission denied'}), 403
            msg['text'] = parse_message(new_text)
            msg['edited'] = True
            save_chat_history(room)
            return jsonify(msg)

    return jsonify({'error': 'Message not found'}), 404

@app.route('/delete_message/<room>/<int:message_id>', methods=['POST'])
@login_required
def delete_message(room, message_id):
    if room not in chat_rooms:
        return jsonify({'error': 'Room not found'}), 404

    for i, msg in enumerate(chat_rooms[room]):
        if msg['id'] == message_id:
            if msg['sender'] != current_user.id and current_user.role not in ['Owner', 'Admin']:
                return jsonify({'error': 'Permission denied'}), 403
            del chat_rooms[room][i]
            save_chat_history(room)
            return jsonify({'success': True})

    return jsonify({'error': 'Message not found'}), 404

@app.route('/report_message/<room>/<int:message_id>', methods=['POST'])
@login_required
def report_message(room, message_id):
    if room not in chat_rooms:
        return jsonify({'error': 'Room not found'}), 404

    data = request.json
    reason = data.get('reason', '')
    message_text = data.get('message_text', '')
    sender = data.get('sender', '')

    if not reason:
        return jsonify({'error': 'Reason required'}), 400

    # Save report to file
    report_data = {
        'reporter': current_user.id,
        'type': 'channel',
        'room': room,
        'message_id': message_id,
        'message_text': message_text,
        'sender': sender,
        'reason': reason,
        'timestamp': datetime.now(cst_timezone).strftime('%Y-%m-%d %I:%M %p'),
    }

    try:
        with open('reports.txt', 'a') as f:
            f.write(json.dumps(report_data) + '\n')
        
        # Notify all non-regular users
        for username, user_data in users.items():
            if user_data['role'] in ['Owner', 'Co-owner', 'Admin', 'Mod']:
                if username not in report_notifications:
                    report_notifications[username] = []
                report_notifications[username].append({
                    'type': 'message_report',
                    'reporter': current_user.id,
                    'room': room,
                    'sender': sender,
                    'reason': reason[:50],
                    'timestamp': report_data['timestamp']
                })
    except Exception as e:
        print(f"Error saving report: {e}")

    return jsonify({'success': True})

@app.route('/add_announcement', methods=['POST'])
@login_required
@requires_role(['Owner', 'Admin'])
def add_announcement():
    text = request.form.get('announcement')
    if text:
        # Apply profanity filter to announcements
        filtered_text = profanity_filter.censor_text(text)
        announcements.append({
            'text': filtered_text,
            'timestamp': datetime.now(cst_timezone).strftime('%Y-%m-%d %I:%M %p'),
            'author': current_user.id
        })
        save_announcements()
        flash('Announcement added successfully!', 'success')
    return redirect(url_for('home'))

def load_friends():
    friends = {}
    friend_requests = {}
    try:
        with open('friends.txt', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                user1, user2, status = line.strip().split('|')
                if status == 'accepted':
                    friends.setdefault(user1, []).append(user2)
                    friends.setdefault(user2, []).append(user1)
                elif status == 'pending':
                    friend_requests.setdefault(user2, []).append(user1)
    except FileNotFoundError:
        pass
    return friends, friend_requests

def save_friends(friends, friend_requests):
    with open('friends.txt', 'w') as f:
        f.write('# Format: username|friend_username|status\n')
        # Save accepted friendships
        for user, friend_list in friends.items():
            for friend in friend_list:
                if user < friend:  # Avoid duplicate entries
                    f.write(f"{user}|{friend}|accepted\n")
        # Save pending requests
        for user, requesters in friend_requests.items():
            for requester in requesters:
                f.write(f"{requester}|{user}|pending\n")

@app.route('/')
@login_required
def home():
    if current_user.is_authenticated:
        friends, friend_requests = load_friends()
        user_friends = friends.get(current_user.id, [])
        user_requests = friend_requests.get(current_user.id, [])
        
        # Load most recent DMs for each friend
        recent_dms = []
        for friend in user_friends:
            messages = load_dm_history(current_user.id, friend)
            if messages:
                recent_dms.append(messages[-1])  # Get most recent message
                
        # Add messages where user was recipient
        for username in users:
            if username != current_user.id:
                messages = load_dm_history(username, current_user.id)
                if messages and messages[-1] not in recent_dms:
                    recent_dms.append(messages[-1])
                    
        # Sort by timestamp (newest first)
        recent_dms.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('index.html', announcements=announcements, users=users, 
                            friends=user_friends, friend_requests=user_requests,
                            active_users=active_users, dm_messages=recent_dms,
                            chat_rooms=chat_rooms)
    return render_template('index.html', announcements=announcements, users=users,
                         chat_rooms=chat_rooms)

@app.route('/send_friend_request/<username>', methods=['POST'])
@login_required
def send_friend_request(username):
    if username not in users or username == current_user.id:
        flash('Invalid friend request')
        return redirect(url_for('view_profile', username=username))

    friends, friend_requests = load_friends()
    if username in friends.get(current_user.id, []):
        flash('Already friends')
        return redirect(url_for('view_profile', username=username))

    if username not in friend_requests:
        friend_requests[username] = []
    if current_user.id not in friend_requests[username]:
        friend_requests[username].append(current_user.id)
        save_friends(friends, friend_requests)
        flash('Friend request sent!')
    else:
        flash('Friend request already sent')

    return redirect(url_for('view_profile', username=username))

@app.route('/respond_friend_request', methods=['POST'])
@login_required
def respond_friend_request():
    username = request.form.get('username')
    action = request.form.get('action')

    if not username or action not in ['accept', 'reject']:
        flash('Invalid request')
        return redirect(url_for('home'))

    friends, friend_requests = load_friends()
    if username not in friend_requests.get(current_user.id, []):
        flash('No friend request found')
        return redirect(url_for('home'))

    friend_requests[current_user.id].remove(username)

    if action == 'accept':
        if current_user.id not in friends:
            friends[current_user.id] = []
        if username not in friends:
            friends[username] = []
        friends[current_user.id].append(username)
        friends[username].append(current_user.id)
        flash('Friend request accepted!')
    else:
        flash('Friend request rejected')

    save_friends(friends, friend_requests)
    return redirect(url_for('home'))

@app.route('/dm/<username>')
@login_required
def direct_message(username):
    if username not in users:
        flash('User not found')
        return redirect(url_for('home'))
    dm_messages = load_dm_history(current_user.id, username)
    friends, _ = load_friends()
    user_friends = friends.get(current_user.id, [])
    return render_template('direct_message.html', 
                         users=users,
                         dm_messages=dm_messages,
                         recipient=username,
                         friends=user_friends,
                         active_users=active_users)

@app.route('/send_dm', methods=['POST'])
@login_required
def send_dm():
    data = request.json
    recipient = data.get('recipient')
    message = data.get('message')

    if not recipient or not message or recipient not in users:
        return jsonify({'success': False, 'error': 'Invalid request'})

    messages = load_dm_history(current_user.id, recipient)
    # Apply profanity filter to direct messages
    filtered_message = profanity_filter.censor_text(message)
    new_message = {
        'sender': current_user.id,
        'recipient': recipient,
        'text': filtered_message,
        'timestamp': datetime.now(cst_timezone).strftime('%Y-%m-%d %I:%M %p'),
    }
    messages.append(new_message)
    save_dm_history(current_user.id, recipient, messages)

    return jsonify({'success': True})

@app.route('/broadcast_troll', methods=['POST'])
@login_required
def broadcast_troll():
    if current_user.role != 'Developer':
        return jsonify({'error': 'Unauthorized'}), 403
    effect = request.json.get('effect')
    if effect:
        troll_effect_queue.append(effect)
        return jsonify({'message': f'Broadcasting {effect}'}), 200
    return jsonify({'error': 'No effect specified'}), 400

troll_effect_queue = []
report_notifications = {}

@app.route('/troll_events')
@login_required
def troll_events():
    def event_stream():
        while True:
            data = {}
            if troll_effect_queue:
                data['effect'] = troll_effect_queue.pop(0)
            
            # Check for report notifications for non-regular users
            if current_user and current_user.is_authenticated and current_user.role in ['Owner', 'Co-owner', 'Admin', 'Mod']:
                if current_user.id in report_notifications:
                    data['reports'] = report_notifications[current_user.id]
                    report_notifications[current_user.id] = []
            
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/report_dm', methods=['POST'])
@login_required
def report_dm():
    data = request.json
    reason = data.get('reason', '')
    message_text = data.get('message_text', '')
    sender = data.get('sender', '')
    recipient = data.get('recipient', '')

    if not reason:
        return jsonify({'error': 'Reason required'}), 400

    # Save report to file
    report_data = {
        'reporter': current_user.id,
        'type': 'dm',
        'message_text': message_text,
        'sender': sender,
        'recipient': recipient,
        'reason': reason,
        'timestamp': datetime.now(cst_timezone).strftime('%Y-%m-%d %I:%M %p'),
    }

    try:
        with open('reports.txt', 'a') as f:
            f.write(json.dumps(report_data) + '\n')
        
        # Notify all non-regular users
        for username, user_data in users.items():
            if user_data['role'] in ['Owner', 'Co-owner', 'Admin', 'Mod']:
                if username not in report_notifications:
                    report_notifications[username] = []
                report_notifications[username].append({
                    'type': 'dm_report',
                    'reporter': current_user.id,
                    'sender': sender,
                    'reason': reason[:50],
                    'timestamp': report_data['timestamp']
                })
    except Exception as e:
        print(f"Error saving DM report: {e}")

    return jsonify({'success': True})

@app.route('/get_dm/<username>')
@login_required
def get_dm(username):
    if username not in users:
        return jsonify({'messages': []})

    messages = load_dm_history(current_user.id, username)
    formatted_messages = [
        {
            'sender': msg['sender'],
            'sender_name': users[msg['sender']]['display_name'],
            'text': msg['text'],
            'timestamp': msg['timestamp']
        }
        for msg in reversed(messages)
    ]

    return jsonify({'messages': formatted_messages})

@app.route('/api/search_users')
@login_required
def search_users():
    query = request.args.get('q', '').lower().strip()
    if not query or len(query) < 2:
        return jsonify({'users': []})
    
    results = []
    for username, data in users.items():
        if username == current_user.id:
            continue
        if query in username.lower() or query in data['display_name'].lower():
            results.append({
                'username': username,
                'display_name': data['display_name'],
                'role': data['role'],
                'profile_pic': data.get('profile_pic', '')
            })
    
    return jsonify({'users': results[:10]})

@app.route('/api/block_user/<username>', methods=['POST'])
@login_required
def block_user(username):
    if username not in users or username == current_user.id:
        return jsonify({'success': False, 'error': 'Invalid user'})
    
    blocked = load_blocked_users()
    if current_user.id not in blocked:
        blocked[current_user.id] = []
    
    if username not in blocked[current_user.id]:
        blocked[current_user.id].append(username)
        save_blocked_users(blocked)
        return jsonify({'success': True, 'message': f'Blocked {username}'})
    return jsonify({'success': False, 'error': 'User already blocked'})

@app.route('/api/unblock_user/<username>', methods=['POST'])
@login_required
def unblock_user(username):
    blocked = load_blocked_users()
    if current_user.id in blocked and username in blocked[current_user.id]:
        blocked[current_user.id].remove(username)
        save_blocked_users(blocked)
        return jsonify({'success': True, 'message': f'Unblocked {username}'})
    return jsonify({'success': False, 'error': 'User not blocked'})

@app.route('/api/blocked_users')
@login_required
def get_blocked_users():
    blocked = load_blocked_users()
    user_blocked = blocked.get(current_user.id, [])
    return jsonify({'blocked': user_blocked})

def load_blocked_users():
    blocked = {}
    try:
        with open('blocked_users.txt', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 2:
                    blocker = parts[0]
                    blocked_user = parts[1]
                    if blocker not in blocked:
                        blocked[blocker] = []
                    blocked[blocker].append(blocked_user)
    except FileNotFoundError:
        pass
    return blocked

def save_blocked_users(blocked):
    with open('blocked_users.txt', 'w') as f:
        f.write('# Format: blocker|blocked_user\n')
        for blocker, blocked_list in blocked.items():
            for blocked_user in blocked_list:
                f.write(f"{blocker}|{blocked_user}\n")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', users=users), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)