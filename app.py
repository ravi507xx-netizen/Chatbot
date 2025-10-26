from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import httpx
import secrets
import sqlite3
import hashlib
from datetime import datetime
from typing import Optional, Dict, List
import os

app = FastAPI(
    title="Pollinations Relay API",
    description="API relay for Pollinations.ai with key management",
    version="2.0.0"
)

# Database setup
def init_db():
    conn = sqlite3.connect('api_keys.db')
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            requests_count INTEGER DEFAULT 0,
            last_used TIMESTAMP
        )
    ''')
    
    # Default admin credentials
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    password_hash = hashlib.sha256("mk123".encode()).hexdigest()
    c.execute('''
        INSERT OR IGNORE INTO admin_users (username, password_hash) 
        VALUES (?, ?)
    ''', ('mk', password_hash))
    
    conn.commit()
    conn.close()

init_db()

# Models
class PollinationsRequest(BaseModel):
    text: str

class APIKeyCreate(BaseModel):
    name: str
    admin_username: str
    admin_password: str

class APIKeyToggle(BaseModel):
    key_id: int
    admin_username: str
    admin_password: str

class APIKeyDelete(BaseModel):
    key_id: int
    admin_username: str
    admin_password: str

# Utility functions
def generate_api_key():
    return f"pk_{secrets.token_urlsafe(24)}"

def get_db_connection():
    conn = sqlite3.connect('api_keys.db')
    conn.row_factory = sqlite3.Row
    return conn

def verify_admin_password(password: str, stored_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash

def authenticate_admin(username: str, password: str) -> bool:
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admin_users WHERE username = ?', 
        (username,)
    ).fetchone()
    conn.close()
    
    if not admin:
        return False
    
    return verify_admin_password(password, admin['password_hash'])

# Client-friendly response format
def client_response(success: bool, message: str, data: Optional[Dict] = None):
    return {
        "success": success,
        "message": message,
        "data": data or {},
        "timestamp": datetime.utcnow().isoformat()
    }

# API Routes
@app.get("/")
async def root():
    return client_response(
        True,
        "Hey! What's on your mind? Looking to start a chat, brainstorm something, or just say hi?",
        {
            "service": "Pollinations Relay API",
            "version": "2.0.0",
            "endpoints": {
                "GET /": "Welcome message",
                "POST /prompt": "Send text to Pollinations.ai (requires X-API-Key header)",
                "GET /keys": "List all API keys (admin auth required)",
                "POST /keys/create": "Create new API key",
                "POST /keys/toggle": "Activate/deactivate key",
                "POST /keys/delete": "Delete key",
                "GET /health": "Health check"
            },
            "admin_credentials": {
                "username": "mk",
                "password": "mk123"
            }
        }
    )

@app.post("/prompt")
async def relay_prompt(
    request: PollinationsRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
):
    # Welcome message for empty prompts
    if not request.text.strip():
        return client_response(
            True,
            "Hey! What's on your mind? Looking to start a chat, brainstorm something, or just say hi?"
        )
    
    # API key validation
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required in X-API-Key header")
    
    conn = get_db_connection()
    key_data = conn.execute(
        'SELECT * FROM api_keys WHERE key = ? AND is_active = 1',
        (x_api_key,)
    ).fetchone()
    
    if not key_data:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    
    # Call Pollinations.ai
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"https://text.pollinations.ai/prompt/{request.text}")
            response.raise_for_status()
            pollinations_response = response.text
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Pollinations.ai error: {str(e)}")
    
    # Update stats
    conn.execute(
        'UPDATE api_keys SET requests_count = requests_count + 1, last_used = CURRENT_TIMESTAMP WHERE key = ?',
        (x_api_key,)
    )
    conn.commit()
    conn.close()
    
    return client_response(
        True,
        pollinations_response,
        {
            "original_prompt": request.text,
            "api_key_used": x_api_key[:8] + "***",
            "requests_count": key_data['requests_count'] + 1
        }
    )

@app.get("/keys")
async def list_keys(admin_username: str, admin_password: str):
    if not authenticate_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    keys = conn.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()
    total_keys = conn.execute('SELECT COUNT(*) FROM api_keys').fetchone()[0]
    active_keys = conn.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = 1').fetchone()[0]
    total_requests = conn.execute('SELECT SUM(requests_count) FROM api_keys').fetchone()[0] or 0
    conn.close()
    
    keys_list = []
    for key in keys:
        keys_list.append({
            "id": key['id'],
            "name": key['name'],
            "key": key['key'],
            "created_at": key['created_at'],
            "is_active": bool(key['is_active']),
            "requests_count": key['requests_count'],
            "last_used": key['last_used']
        })
    
    return client_response(
        True,
        f"Found {total_keys} API keys",
        {
            "stats": {
                "total_keys": total_keys,
                "active_keys": active_keys,
                "total_requests": total_requests
            },
            "keys": keys_list
        }
    )

@app.post("/keys/create")
async def create_api_key(request: APIKeyCreate):
    if not authenticate_admin(request.admin_username, request.admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    new_key = generate_api_key()
    
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO api_keys (key, name) VALUES (?, ?)',
            (new_key, request.name)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Key generation failed, try again")
    
    conn.close()
    
    return client_response(
        True,
        f"API key '{request.name}' created successfully",
        {
            "name": request.name,
            "api_key": new_key,
            "message": "Save this key securely - it won't be shown again!"
        }
    )

@app.post("/keys/toggle")
async def toggle_api_key(request: APIKeyToggle):
    if not authenticate_admin(request.admin_username, request.admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM api_keys WHERE id = ?', (request.key_id,)).fetchone()
    
    if not key:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found")
    
    new_status = not key['is_active']
    conn.execute(
        'UPDATE api_keys SET is_active = ? WHERE id = ?',
        (new_status, request.key_id)
    )
    conn.commit()
    conn.close()
    
    status_text = "activated" if new_status else "deactivated"
    
    return client_response(
        True,
        f"API key '{key['name']}' has been {status_text}",
        {
            "key_id": request.key_id,
            "name": key['name'],
            "is_active": new_status
        }
    )

@app.post("/keys/delete")
async def delete_api_key(request: APIKeyDelete):
    if not authenticate_admin(request.admin_username, request.admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM api_keys WHERE id = ?', (request.key_id,)).fetchone()
    
    if not key:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found")
    
    conn.execute('DELETE FROM api_keys WHERE id = ?', (request.key_id,))
    conn.commit()
    conn.close()
    
    return client_response(
        True,
        f"API key '{key['name']}' has been deleted",
        {
            "key_id": request.key_id,
            "name": key['name']
        }
    )

@app.get("/health")
async def health_check():
    conn = get_db_connection()
    db_status = conn.execute('SELECT 1').fetchone() is not None
    conn.close()
    
    return client_response(
        True,
        "Service is healthy and running",
        {
            "status": "healthy",
            "database": "connected" if db_status else "disconnected",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
