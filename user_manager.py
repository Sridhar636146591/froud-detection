"""
User Manager Module
Handles all user-related operations using JSON file storage
"""

import json
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Path to the users JSON file
USERS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'all_users.json')


def load_users():
    """Load all users from JSON file"""
    if not os.path.exists(USERS_FILE):
        return {"metadata": {}, "users": []}
    
    with open(USERS_FILE, 'r') as f:
        return json.load(f)


def save_users(data):
    """Save users to JSON file"""
    # Update metadata
    data['metadata']['last_updated'] = datetime.now().isoformat()
    data['metadata']['total_users'] = len(data['users'])
    
    with open(USERS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def get_all_users():
    """Get list of all users (without passwords)"""
    data = load_users()
    # Remove passwords from response
    users = []
    for user in data['users']:
        user_copy = user.copy()
        user_copy.pop('password', None)
        users.append(user_copy)
    return users


def get_user_by_username(username):
    """Get user by username"""
    data = load_users()
    for user in data['users']:
        if user['username'] == username:
            return user
    return None


def get_user_by_id(user_id):
    """Get user by ID"""
    data = load_users()
    for user in data['users']:
        if user['id'] == user_id:
            return user
    return None


def add_user(username, password, email, full_name, role='officer', department=''):
    """Add a new user"""
    data = load_users()
    
    # Check if username already exists
    if get_user_by_username(username):
        return False, "Username already exists"
    
    # Generate new ID
    new_id = max([u['id'] for u in data['users']], default=0) + 1
    
    # Create new user
    new_user = {
        "id": new_id,
        "username": username,
        "password": password,  # Store plain password (in production, hash this)
        "email": email,
        "full_name": full_name,
        "role": role,
        "department": department,
        "email_verified": True,
        "created_at": datetime.now().isoformat(),
        "is_active": True,
        "last_login": None
    }
    
    data['users'].append(new_user)
    save_users(data)
    return True, "User created successfully"


def update_user(user_id, **kwargs):
    """Update user information"""
    data = load_users()
    
    for user in data['users']:
        if user['id'] == user_id:
            # Update fields
            for key, value in kwargs.items():
                if key in user and key != 'id':
                    user[key] = value
            
            save_users(data)
            return True, "User updated successfully"
    
    return False, "User not found"


def delete_user(user_id):
    """Delete a user"""
    data = load_users()
    
    for i, user in enumerate(data['users']):
        if user['id'] == user_id:
            data['users'].pop(i)
            save_users(data)
            return True, "User deleted successfully"
    
    return False, "User not found"


def verify_user_credentials(username, password):
    """Verify user credentials"""
    user = get_user_by_username(username)
    if user and user['password'] == password:
        # Update last login
        update_user(user['id'], last_login=datetime.now().isoformat())
        return user
    return None


def change_password(user_id, new_password):
    """Change user password"""
    return update_user(user_id, password=new_password)


def export_to_sqlite():
    """Export all users from JSON to SQLite database"""
    from database import get_db_connection, create_user
    
    data = load_users()
    conn = get_db_connection()
    
    for user in data['users']:
        # Check if user already exists in DB
        existing = conn.execute('SELECT id FROM users WHERE username = ?', 
                               (user['username'],)).fetchone()
        if not existing:
            create_user(
                username=user['username'],
                email=user['email'],
                password=user['password'],
                full_name=user['full_name'],
                role=user['role'],
                department=user['department']
            )
            # Update email_verified status
            conn.execute('UPDATE users SET email_verified = ? WHERE username = ?',
                        (1 if user.get('email_verified', False) else 0, user['username']))
    
    conn.commit()
    conn.close()
    return True, "Users exported to SQLite successfully"


def sync_from_sqlite():
    """Sync users from SQLite to JSON file"""
    from database import get_db_connection
    
    conn = get_db_connection()
    db_users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    data = load_users()
    existing_usernames = {u['username'] for u in data['users']}
    
    for db_user in db_users:
        if db_user['username'] not in existing_usernames:
            new_user = {
                "id": db_user['id'],
                "username": db_user['username'],
                "password": "",  # Password not stored in SQLite (only hash)
                "email": db_user['email'],
                "full_name": db_user['full_name'],
                "role": db_user['role'],
                "department": db_user['department'],
                "email_verified": bool(db_user.get('email_verified', 0)),
                "created_at": db_user.get('created_at', datetime.now().isoformat()),
                "is_active": True,
                "last_login": None
            }
            data['users'].append(new_user)
    
    save_users(data)
    return True, "Users synced from SQLite successfully"


if __name__ == '__main__':
    # Test the module
    print("Users in JSON file:")
    for user in get_all_users():
        print(f"  - {user['username']} ({user['role']}): {user['full_name']}")
