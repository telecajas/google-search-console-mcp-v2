"""
Remote MCP Server for Google Search Console with OAuth 2.0 Web Authentication

This server can be hosted online and allows users to authenticate via OAuth 2.0
web flow instead of local credential files.

Architecture:
1. User visits your web app and logs in with Google OAuth
2. Server stores the user's GSC access token
3. User configures Claude to connect to your remote MCP server
4. MCP server uses the stored token to access GSC on behalf of the user

Requirements:
    pip install -r requirements.txt

Run locally:
    uvicorn gsc_server_remote:app --host 0.0.0.0 --port 8000

Environment Variables:
    GOOGLE_CLIENT_ID     - Your Google OAuth client ID
    GOOGLE_CLIENT_SECRET - Your Google OAuth client secret  
    GOOGLE_REDIRECT_URI  - OAuth callback URL (default: http://localhost:8000/oauth/callback)
    SECRET_KEY           - Secret key for sessions (auto-generated if not set)
    DATABASE_URL         - Database URL (default: sqlite:///./gsc_tokens.db)
"""

import os
import json
import secrets
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path
from contextlib import asynccontextmanager

# Web framework
from fastapi import FastAPI, Request, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Google OAuth
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# MCP
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport

# Database (simple SQLite for demo, use PostgreSQL in production)
import sqlite3
from contextlib import contextmanager

# =============================================================================
# CONFIGURATION
# =============================================================================

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8000/oauth/callback")

# Server configuration
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE_PATH = os.environ.get("DATABASE_PATH", "gsc_tokens.db")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")

# Scopes for Google Search Console
SCOPES = [
    "https://www.googleapis.com/auth/webmasters",
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/indexing",
    "openid"
]

# =============================================================================
# DATABASE
# =============================================================================

def init_database():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            credentials TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used TEXT,
            is_active INTEGER DEFAULT 1
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

@contextmanager
def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def save_user(user_id: str, email: str, credentials: dict):
    """Save user credentials to database."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO users (id, email, credentials, created_at, last_used, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (user_id, email, json.dumps(credentials), datetime.now().isoformat(), datetime.now().isoformat()))
        conn.commit()

def get_user(user_id: str) -> Optional[dict]:
    """Get user from database."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,))
        row = cursor.fetchone()
        if row:
            # Update last used
            cursor.execute("UPDATE users SET last_used = ? WHERE id = ?", (datetime.now().isoformat(), user_id))
            conn.commit()
            return {
                "id": row["id"],
                "email": row["email"],
                "credentials": json.loads(row["credentials"]),
                "created_at": row["created_at"],
                "last_used": row["last_used"]
            }
        return None

def delete_user(user_id: str):
    """Delete/deactivate user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        conn.commit()

def save_oauth_state(state: str):
    """Save OAuth state for CSRF protection."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO oauth_states (state, created_at) VALUES (?, ?)", 
                      (state, datetime.now().isoformat()))
        conn.commit()

def verify_oauth_state(state: str) -> bool:
    """Verify and consume OAuth state."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM oauth_states WHERE state = ?", (state,))
        row = cursor.fetchone()
        if row:
            cursor.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
            conn.commit()
            return True
        return False

def cleanup_old_states():
    """Clean up OAuth states older than 10 minutes."""
    with get_db() as conn:
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(minutes=10)).isoformat()
        cursor.execute("DELETE FROM oauth_states WHERE created_at < ?", (cutoff,))
        conn.commit()

# =============================================================================
# FASTAPI APP
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    init_database()
    yield
    # Shutdown

app = FastAPI(
    title="GSC MCP Server",
    description="Remote MCP Server for Google Search Console with OAuth 2.0",
    version="2.0.0",
    lifespan=lifespan
)

# Session middleware for OAuth
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# CORS for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# OAUTH 2.0 WEB FLOW
# =============================================================================

def get_oauth_flow() -> Flow:
    """Create an OAuth flow for the web application."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set")
    
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_REDIRECT_URI]
        }
    }
    
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = GOOGLE_REDIRECT_URI
    
    return flow


# =============================================================================
# WEB PAGES
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    """Home page with login button."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GSC MCP Server - Connect Claude to Google Search Console</title>
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: 'Space Grotesk', system-ui, sans-serif;
                background: #0a0a0f;
                min-height: 100vh;
                color: #e0e0e0;
                overflow-x: hidden;
            }
            
            /* Animated background */
            .bg-grid {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-image: 
                    linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
                background-size: 50px 50px;
                animation: gridMove 20s linear infinite;
            }
            
            @keyframes gridMove {
                0% { transform: translate(0, 0); }
                100% { transform: translate(50px, 50px); }
            }
            
            .glow-orb {
                position: fixed;
                width: 600px;
                height: 600px;
                border-radius: 50%;
                filter: blur(120px);
                opacity: 0.15;
                pointer-events: none;
            }
            
            .orb-1 {
                top: -200px;
                right: -200px;
                background: #00ff88;
            }
            
            .orb-2 {
                bottom: -200px;
                left: -200px;
                background: #0088ff;
            }
            
            .container {
                position: relative;
                z-index: 1;
                max-width: 1200px;
                margin: 0 auto;
                padding: 2rem;
            }
            
            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1rem 0;
                margin-bottom: 4rem;
            }
            
            .logo {
                font-size: 1.5rem;
                font-weight: 700;
                color: #00ff88;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            
            .hero {
                text-align: center;
                padding: 4rem 0;
            }
            
            .badge {
                display: inline-block;
                background: rgba(0, 255, 136, 0.1);
                border: 1px solid rgba(0, 255, 136, 0.3);
                color: #00ff88;
                padding: 0.5rem 1rem;
                border-radius: 50px;
                font-size: 0.85rem;
                margin-bottom: 2rem;
            }
            
            h1 {
                font-size: clamp(2.5rem, 6vw, 4rem);
                font-weight: 700;
                line-height: 1.1;
                margin-bottom: 1.5rem;
                background: linear-gradient(135deg, #ffffff 0%, #00ff88 50%, #0088ff 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            .subtitle {
                font-size: 1.25rem;
                color: #888;
                max-width: 600px;
                margin: 0 auto 3rem;
                line-height: 1.6;
            }
            
            .btn-primary {
                display: inline-flex;
                align-items: center;
                gap: 12px;
                padding: 16px 32px;
                font-size: 1.1rem;
                font-weight: 600;
                color: #0a0a0f;
                background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
                border: none;
                border-radius: 12px;
                cursor: pointer;
                text-decoration: none;
                transition: all 0.3s ease;
                box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
            }
            
            .btn-primary:hover {
                transform: translateY(-3px);
                box-shadow: 0 0 50px rgba(0, 255, 136, 0.5);
            }
            
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 1.5rem;
                margin-top: 6rem;
            }
            
            .feature-card {
                background: rgba(255, 255, 255, 0.02);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 16px;
                padding: 2rem;
                transition: all 0.3s ease;
            }
            
            .feature-card:hover {
                background: rgba(255, 255, 255, 0.05);
                border-color: rgba(0, 255, 136, 0.3);
                transform: translateY(-5px);
            }
            
            .feature-icon {
                font-size: 2rem;
                margin-bottom: 1rem;
            }
            
            .feature-card h3 {
                font-size: 1.2rem;
                color: #fff;
                margin-bottom: 0.75rem;
            }
            
            .feature-card p {
                color: #888;
                line-height: 1.6;
            }
            
            .how-it-works {
                margin-top: 6rem;
                text-align: center;
            }
            
            .how-it-works h2 {
                font-size: 2rem;
                margin-bottom: 3rem;
                color: #fff;
            }
            
            .steps {
                display: flex;
                justify-content: center;
                gap: 2rem;
                flex-wrap: wrap;
            }
            
            .step {
                text-align: center;
                max-width: 200px;
            }
            
            .step-number {
                width: 50px;
                height: 50px;
                border-radius: 50%;
                background: linear-gradient(135deg, #00ff88, #0088ff);
                color: #0a0a0f;
                font-weight: 700;
                font-size: 1.2rem;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 1rem;
            }
            
            .step h4 {
                color: #fff;
                margin-bottom: 0.5rem;
            }
            
            .step p {
                color: #888;
                font-size: 0.9rem;
            }
            
            footer {
                margin-top: 6rem;
                padding: 2rem 0;
                text-align: center;
                border-top: 1px solid rgba(255, 255, 255, 0.08);
                color: #666;
            }
            
            footer a {
                color: #00ff88;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="bg-grid"></div>
        <div class="glow-orb orb-1"></div>
        <div class="glow-orb orb-2"></div>
        
        <div class="container">
            <header>
                <a href="/" class="logo">
                    <span>Ã°ÂÂÂ</span> GSC MCP
                </a>
            </header>
            
            <section class="hero">
                <span class="badge">Ã¢ÂÂ¨ Now with OAuth 2.0</span>
                <h1>Connect Claude AI to<br>Google Search Console</h1>
                <p class="subtitle">
                    Analyze your SEO data through natural conversations. 
                    No API keys to manageÃ¢ÂÂjust sign in with Google and start chatting.
                </p>
                <a href="/oauth/login" class="btn-primary">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Sign in with Google
                </a>
            </section>
            
            <section class="features">
                <div class="feature-card">
                    <div class="feature-icon">Ã°ÂÂÂ</div>
                    <h3>Search Analytics</h3>
                    <p>Get detailed insights into your search performance, top queries, and click-through rates.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">Ã°ÂÂÂ¯</div>
                    <h3>Keyword Opportunities</h3>
                    <p>Discover keywords where you're ranking but could improve with optimization.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">Ã°ÂÂÂ</div>
                    <h3>URL Inspection</h3>
                    <p>Check indexing status, crawl errors, and rich results for any page.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">Ã°ÂÂÂºÃ¯Â¸Â</div>
                    <h3>Sitemap Management</h3>
                    <p>Submit, monitor, and manage your sitemaps directly through Claude.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">Ã°ÂÂÂ±</div>
                    <h3>Device Comparison</h3>
                    <p>Compare mobile vs desktop performance and identify optimization opportunities.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">Ã°ÂÂÂ¤</div>
                    <h3>Export Data</h3>
                    <p>Export your analytics data to CSV or JSON for further analysis.</p>
                </div>
            </section>
            
            <section class="how-it-works">
                <h2>How It Works</h2>
                <div class="steps">
                    <div class="step">
                        <div class="step-number">1</div>
                        <h4>Sign In</h4>
                        <p>Authenticate with your Google account</p>
                    </div>
                    <div class="step">
                        <div class="step-number">2</div>
                        <h4>Get Your Key</h4>
                        <p>Receive a unique API key for Claude</p>
                    </div>
                    <div class="step">
                        <div class="step-number">3</div>
                        <h4>Configure</h4>
                        <p>Add the config to Claude Desktop</p>
                    </div>
                    <div class="step">
                        <div class="step-number">4</div>
                        <h4>Chat!</h4>
                        <p>Ask Claude about your SEO data</p>
                    </div>
                </div>
            </section>
            
            <footer>
                <p>Created by <a href="https://aminforoutan.com" target="_blank">Amin Foroutan</a> Ã¢ÂÂ¢ 
                <a href="https://github.com/AminForou/google-search-console-mcp-v2" target="_blank">GitHub</a></p>
            </footer>
        </div>
    </body>
    </html>
    """


@app.get("/oauth/login")
async def oauth_login(request: Request):
    """Initiate OAuth login flow."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return HTMLResponse(
            """<html><body style="background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;">
            <div style="text-align:center;max-width:500px;padding:2rem;">
            <h1 style="color:#ff4444;">Configuration Error</h1>
            <p>Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.</p>
            </div></body></html>""",
            status_code=500
        )
    
    # Clean up old states
    cleanup_old_states()
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    save_oauth_state(state)
    
    flow = get_oauth_flow()
    flow.autogenerate_code_verifier = False  # Disable PKCE
    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        state=state,
        prompt='consent'
    )
    
    return RedirectResponse(authorization_url)


@app.get("/oauth/callback")
async def oauth_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Handle OAuth callback from Google."""
    
    if error:
        return HTMLResponse(
            f"""<html><body style="background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;">
            <div style="text-align:center;"><h1 style="color:#ff4444;">Authentication Error</h1><p>{error}</p>
            <a href="/" style="color:#00ff88;">Try again</a></div></body></html>""",
            status_code=400
        )
    
    if not state or not verify_oauth_state(state):
        return HTMLResponse(
            """<html><body style="background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;">
            <div style="text-align:center;"><h1 style="color:#ff4444;">Invalid State</h1><p>Please try again.</p>
            <a href="/" style="color:#00ff88;">Go back</a></div></body></html>""",
            status_code=400
        )
    
    try:
        flow = get_oauth_flow()
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        # Get user info
        user_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_service.userinfo().get().execute()
        email = user_info.get('email', 'unknown')
        
        # Generate unique user ID
        user_id = secrets.token_urlsafe(20)
        
        # Store credentials
        cred_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": list(credentials.scopes) if credentials.scopes else SCOPES
        }
        save_user(user_id, email, cred_data)
        
        # Success page
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Authentication Successful - GSC MCP Server</title>
            <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Space Grotesk', system-ui, sans-serif;
                    background: #0a0a0f;
                    min-height: 100vh;
                    color: #e0e0e0;
                    padding: 2rem;
                }}
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                }}
                .success-header {{
                    text-align: center;
                    padding: 3rem 0;
                }}
                .success-icon {{
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }}
                h1 {{
                    color: #00ff88;
                    font-size: 2rem;
                    margin-bottom: 0.5rem;
                }}
                .email {{
                    color: #888;
                }}
                .card {{
                    background: rgba(255, 255, 255, 0.03);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 16px;
                    padding: 2rem;
                    margin: 1.5rem 0;
                }}
                .card h3 {{
                    color: #fff;
                    margin-bottom: 1rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }}
                .api-key {{
                    background: rgba(0, 255, 136, 0.1);
                    border: 1px solid rgba(0, 255, 136, 0.3);
                    padding: 1rem;
                    border-radius: 8px;
                    font-family: 'JetBrains Mono', monospace;
                    color: #00ff88;
                    word-break: break-all;
                    position: relative;
                }}
                .copy-btn {{
                    position: absolute;
                    right: 10px;
                    top: 50%;
                    transform: translateY(-50%);
                    background: rgba(0, 255, 136, 0.2);
                    border: none;
                    color: #00ff88;
                    padding: 0.5rem 1rem;
                    border-radius: 6px;
                    cursor: pointer;
                    font-family: inherit;
                }}
                .copy-btn:hover {{
                    background: rgba(0, 255, 136, 0.3);
                }}
                .code-block {{
                    background: #1a1a24;
                    border-radius: 8px;
                    padding: 1rem;
                    overflow-x: auto;
                }}
                .code-block pre {{
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 0.85rem;
                    color: #e0e0e0;
                    white-space: pre-wrap;
                }}
                .warning {{
                    background: rgba(255, 193, 7, 0.1);
                    border: 1px solid rgba(255, 193, 7, 0.3);
                    color: #ffc107;
                    padding: 1rem;
                    border-radius: 8px;
                    margin-top: 1.5rem;
                    display: flex;
                    gap: 0.75rem;
                }}
                .steps {{
                    counter-reset: step;
                }}
                .step {{
                    counter-increment: step;
                    padding: 1rem 0;
                    padding-left: 3rem;
                    position: relative;
                    border-left: 2px solid rgba(255,255,255,0.1);
                }}
                .step:before {{
                    content: counter(step);
                    position: absolute;
                    left: -15px;
                    width: 28px;
                    height: 28px;
                    background: linear-gradient(135deg, #00ff88, #0088ff);
                    border-radius: 50%;
                    color: #0a0a0f;
                    font-weight: 700;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 0.85rem;
                }}
                .step h4 {{
                    color: #fff;
                    margin-bottom: 0.5rem;
                }}
                .step p {{
                    color: #888;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success-header">
                    <div class="success-icon">Ã¢ÂÂ</div>
                    <h1>Authentication Successful!</h1>
                    <p class="email">Logged in as: {email}</p>
                </div>
                
                <div class="card">
                    <h3>Ã°ÂÂÂ Your API Key</h3>
                    <div class="api-key">
                        {user_id}
                        <button class="copy-btn" onclick="navigator.clipboard.writeText('{user_id}')">Copy</button>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Ã¢ÂÂÃ¯Â¸Â Setup Instructions</h3>
                    <div class="steps">
                        <div class="step">
                            <h4>Open Claude Desktop Config</h4>
                            <p>
                                <strong>Mac:</strong> <code>~/Library/Application Support/Claude/claude_desktop_config.json</code><br>
                                <strong>Windows:</strong> <code>%APPDATA%\\Claude\\claude_desktop_config.json</code>
                            </p>
                        </div>
                        <div class="step">
                            <h4>Add This Configuration</h4>
                            <div class="code-block">
                                <pre>{{
  "mcpServers": {{
    "gscServer": {{
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "{BASE_URL}/mcp/{user_id}/sse"
      ]
    }}
  }}
}}</pre>
                            </div>
                        </div>
                        <div class="step">
                            <h4>Restart Claude Desktop</h4>
                            <p>Close and reopen Claude Desktop to load the new configuration.</p>
                        </div>
                        <div class="step">
                            <h4>Start Chatting!</h4>
                            <p>Ask Claude: "List my GSC properties" or "Show me my top search queries"</p>
                        </div>
                    </div>
                </div>
                
                <div class="warning">
                    <span>Ã¢ÂÂ Ã¯Â¸Â</span>
                    <div>
                        <strong>Keep your API key secret!</strong>
                        <p>Anyone with this key can access your Google Search Console data.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """)
        
    except Exception as e:
        return HTMLResponse(
            f"""<html><body style="background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;">
            <div style="text-align:center;max-width:500px;"><h1 style="color:#ff4444;">Authentication Failed</h1><p>{str(e)}</p>
            <a href="/" style="color:#00ff88;">Try again</a></div></body></html>""",
            status_code=500
        )


@app.get("/oauth/revoke/{user_id}")
async def revoke_access(user_id: str):
    """Revoke user access."""
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    delete_user(user_id)
    return {"status": "revoked", "message": "Access has been revoked"}


# =============================================================================
# HELPER FUNCTIONS FOR MCP
# =============================================================================

def get_user_credentials(user_id: str) -> Credentials:
    """Get Google credentials for a specific user."""
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated. Please login first.")
    
    cred_data = user["credentials"]
    
    credentials = Credentials(
        token=cred_data["token"],
        refresh_token=cred_data.get("refresh_token"),
        token_uri=cred_data["token_uri"],
        client_id=cred_data["client_id"],
        client_secret=cred_data["client_secret"],
        scopes=cred_data["scopes"]
    )
    
    # Refresh if expired
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(GoogleRequest())
        # Update stored token
        cred_data["token"] = credentials.token
        save_user(user_id, user["email"], cred_data)
    
    return credentials


def get_gsc_service_for_user(user_id: str):
    """Get GSC service for a specific user."""
    credentials = get_user_credentials(user_id)
    return build("searchconsole", "v1", credentials=credentials)


def get_indexing_service_for_user(user_id: str):
    """Get Indexing API service for a specific user."""
    credentials = get_user_credentials(user_id)
    return build("indexing", "v3", credentials=credentials)


# =============================================================================
# MCP SERVER
# =============================================================================

mcp = FastMCP("gsc-server-remote")

# Current user context (thread-local in production)
_current_user_id: Optional[str] = None

def set_current_user(user_id: str):
    global _current_user_id
    _current_user_id = user_id

def get_current_user() -> str:
    if not _current_user_id:
        raise ValueError("No user context set")
    return _current_user_id


# =============================================================================
# MCP TOOLS
# =============================================================================

@mcp.tool()
async def list_properties() -> str:
    """List all GSC properties for the authenticated user."""
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        site_list = service.sites().list().execute()
        sites = site_list.get("siteEntry", [])

        if not sites:
            return "No Search Console properties found."

        lines = ["# Your Search Console Properties\n"]
        for site in sites:
            site_url = site.get("siteUrl", "Unknown")
            permission = site.get("permissionLevel", "Unknown")
            lines.append(f"- {site_url} ({permission})")

        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_search_analytics(site_url: str, days: int = 28, dimensions: str = "query") -> str:
    """
    Get search analytics data for a property.
    
    Args:
        site_url: The URL of the site in Search Console
        days: Number of days to look back (default: 28)
        dimensions: Dimensions to group by (query, page, device, country, date). Comma-separated.
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": dimension_list,
            "rowLimit": 25
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No data found for {site_url} in the last {days} days."
        
        lines = [f"# Search Analytics: {site_url}\n*Last {days} days*\n"]
        
        header = [d.capitalize() for d in dimension_list] + ["Clicks", "Impr", "CTR", "Pos"]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join(["---"] * len(header)) + "|")
        
        for row in response.get("rows", []):
            data = [str(k)[:50] for k in row.get("keys", [])]
            data.extend([
                str(row.get("clicks", 0)),
                str(row.get("impressions", 0)),
                f"{row.get('ctr', 0) * 100:.1f}%",
                f"{row.get('position', 0):.1f}"
            ])
            lines.append("| " + " | ".join(data) + " |")
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_performance_overview(site_url: str, days: int = 28) -> str:
    """
    Get a performance overview for a property.
    
    Args:
        site_url: The URL of the site in Search Console
        days: Number of days to look back (default: 28)
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": [],
            "rowLimit": 1
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No data found for {site_url}"
        
        row = response["rows"][0]
        lines = [
            f"# Performance Overview: {site_url}\n",
            f"*Last {days} days*\n",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Clicks | {row.get('clicks', 0):,} |",
            f"| Impressions | {row.get('impressions', 0):,} |",
            f"| CTR | {row.get('ctr', 0) * 100:.2f}% |",
            f"| Avg Position | {row.get('position', 0):.1f} |"
        ]
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def find_keyword_opportunities(
    site_url: str,
    days: int = 28,
    min_impressions: int = 100,
    max_position: float = 20.0,
    min_position: float = 4.0
) -> str:
    """
    Find keyword opportunities - queries with high impressions but room for improvement.
    
    Args:
        site_url: The URL of the site in Search Console
        days: Number of days to analyze (default: 28)
        min_impressions: Minimum impressions (default: 100)
        max_position: Maximum position (default: 20)
        min_position: Minimum position - exclude top rankings (default: 4)
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["query", "page"],
            "rowLimit": 5000
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No data found for {site_url}"
        
        opportunities = []
        for row in response.get("rows", []):
            position = row.get("position", 0)
            impressions = row.get("impressions", 0)
            
            if min_position <= position <= max_position and impressions >= min_impressions:
                ctr = row.get("ctr", 0)
                potential = impressions * (1 - ctr) * (1 / position)
                
                opportunities.append({
                    "query": row.get("keys", ["", ""])[0],
                    "page": row.get("keys", ["", ""])[1],
                    "clicks": row.get("clicks", 0),
                    "impressions": impressions,
                    "ctr": ctr,
                    "position": position,
                    "potential": potential
                })
        
        opportunities.sort(key=lambda x: x["potential"], reverse=True)
        
        lines = [f"# Ã°ÂÂÂ¯ Keyword Opportunities: {site_url}"]
        lines.append(f"*Last {days} days | Position {min_position}-{max_position} | Min {min_impressions} impressions*\n")
        
        if not opportunities:
            lines.append("No opportunities found. Try adjusting the filters.")
            return "\n".join(lines)
        
        lines.append(f"Found **{len(opportunities)}** opportunities. Top 20:\n")
        lines.append("| Query | Position | Impressions | CTR | Clicks |")
        lines.append("|-------|----------|-------------|-----|--------|")
        
        for opp in opportunities[:20]:
            lines.append(
                f"| {opp['query'][:40]} | {opp['position']:.1f} | {opp['impressions']:,} | "
                f"{opp['ctr'] * 100:.1f}% | {opp['clicks']} |"
            )
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_top_pages(site_url: str, days: int = 28, limit: int = 20) -> str:
    """
    Get the top performing pages.
    
    Args:
        site_url: The URL of the site
        days: Number of days to analyze (default: 28)
        limit: Number of pages to return (default: 20)
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["page"],
            "rowLimit": limit,
            "orderBy": [{"metric": "CLICK_COUNT", "direction": "descending"}]
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No page data found for {site_url}"
        
        lines = [f"# Ã°ÂÂÂ Top Pages: {site_url}\n*Last {days} days*\n"]
        lines.append("| # | Page | Clicks | Impressions | CTR | Position |")
        lines.append("|---|------|--------|-------------|-----|----------|")
        
        for i, row in enumerate(response.get("rows", []), 1):
            page = row.get("keys", [""])[0]
            display_page = page.replace(site_url.rstrip('/'), '')[:45] or page[:45]
            
            lines.append(
                f"| {i} | {display_page} | {row.get('clicks', 0):,} | {row.get('impressions', 0):,} | "
                f"{row.get('ctr', 0) * 100:.1f}% | {row.get('position', 0):.1f} |"
            )
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_device_comparison(site_url: str, days: int = 28) -> str:
    """
    Compare performance across devices (mobile, desktop, tablet).
    
    Args:
        site_url: The URL of the site
        days: Number of days to analyze (default: 28)
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["device"],
            "rowLimit": 10
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No device data found for {site_url}"
        
        lines = [f"# Ã°ÂÂÂ± Device Comparison: {site_url}\n*Last {days} days*\n"]
        
        total_clicks = sum(row.get("clicks", 0) for row in response.get("rows", []))
        
        lines.append("| Device | Clicks | Share | Impressions | CTR | Position |")
        lines.append("|--------|--------|-------|-------------|-----|----------|")
        
        icons = {"MOBILE": "Ã°ÂÂÂ±", "DESKTOP": "Ã°ÂÂÂ¥Ã¯Â¸Â", "TABLET": "Ã°ÂÂÂ²"}
        
        for row in response.get("rows", []):
            device = row.get("keys", ["Unknown"])[0]
            clicks = row.get("clicks", 0)
            share = (clicks / total_clicks * 100) if total_clicks > 0 else 0
            icon = icons.get(device.upper(), "")
            
            lines.append(
                f"| {icon} {device} | {clicks:,} | {share:.1f}% | {row.get('impressions', 0):,} | "
                f"{row.get('ctr', 0) * 100:.1f}% | {row.get('position', 0):.1f} |"
            )
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_country_breakdown(site_url: str, days: int = 28, limit: int = 15) -> str:
    """
    Get traffic breakdown by country.
    
    Args:
        site_url: The URL of the site
        days: Number of days to analyze (default: 28)
        limit: Number of countries to show (default: 15)
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["country"],
            "rowLimit": limit,
            "orderBy": [{"metric": "CLICK_COUNT", "direction": "descending"}]
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No country data found for {site_url}"
        
        lines = [f"# Ã°ÂÂÂ Country Breakdown: {site_url}\n*Last {days} days*\n"]
        
        total_clicks = sum(row.get("clicks", 0) for row in response.get("rows", []))
        
        lines.append("| Country | Clicks | Share | Impressions | CTR | Position |")
        lines.append("|---------|--------|-------|-------------|-----|----------|")
        
        for row in response.get("rows", []):
            country = row.get("keys", ["Unknown"])[0]
            clicks = row.get("clicks", 0)
            share = (clicks / total_clicks * 100) if total_clicks > 0 else 0
            
            lines.append(
                f"| {country} | {clicks:,} | {share:.1f}% | {row.get('impressions', 0):,} | "
                f"{row.get('ctr', 0) * 100:.1f}% | {row.get('position', 0):.1f} |"
            )
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def inspect_url(site_url: str, page_url: str) -> str:
    """
    Inspect a URL's indexing status.
    
    Args:
        site_url: The site in Search Console (use sc-domain:example.com for domain properties)
        page_url: The URL to inspect
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        request = {"inspectionUrl": page_url, "siteUrl": site_url}
        response = service.urlInspection().index().inspect(body=request).execute()
        
        if not response or "inspectionResult" not in response:
            return f"No inspection data for {page_url}"
        
        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})
        
        verdict = index_status.get("verdict", "UNKNOWN")
        emoji = "Ã¢ÂÂ" if verdict == "PASS" else "Ã¢ÂÂ"
        
        lines = [
            f"# URL Inspection: {page_url}\n",
            f"## Status: {emoji} {verdict}\n",
            f"**Coverage:** {index_status.get('coverageState', 'Unknown')}",
            f"**Robots.txt:** {index_status.get('robotsTxtState', 'Unknown')}",
            f"**Indexing:** {index_status.get('indexingState', 'Unknown')}"
        ]
        
        if "lastCrawlTime" in index_status:
            lines.append(f"**Last Crawl:** {index_status['lastCrawlTime']}")
        
        if "googleCanonical" in index_status:
            lines.append(f"**Google Canonical:** {index_status['googleCanonical']}")
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_sitemaps(site_url: str) -> str:
    """
    List all sitemaps for a property.
    
    Args:
        site_url: The site in Search Console
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        sitemaps = service.sitemaps().list(siteUrl=site_url).execute()
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}"
        
        lines = [f"# Sitemaps: {site_url}\n"]
        lines.append("| Sitemap | URLs | Status |")
        lines.append("|---------|------|--------|")
        
        for sitemap in sitemaps.get("sitemap", []):
            path = sitemap.get("path", "Unknown").split("/")[-1][:35]
            errors = sitemap.get("errors", 0)
            status = "Ã¢ÂÂ" if errors == 0 else f"Ã¢ÂÂ Ã¯Â¸Â {errors} errors"
            
            url_count = "N/A"
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        url_count = str(content.get("submitted", 0))
                        break
            
            lines.append(f"| {path} | {url_count} | {status} |")
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def submit_sitemap(site_url: str, sitemap_url: str) -> str:
    """
    Submit a sitemap to Google.
    
    Args:
        site_url: The site in Search Console
        sitemap_url: The full URL of the sitemap
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        service.sitemaps().submit(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        return f"Ã¢ÂÂ Sitemap submitted: {sitemap_url}\n\nGoogle will process it shortly."
    except Exception as e:
        return f"Error submitting sitemap: {str(e)}"


@mcp.tool()
async def request_indexing(url: str) -> str:
    """
    Request Google to crawl and index a URL.
    Note: Works best for JobPosting and BroadcastEvent pages.
    
    Args:
        url: The URL to request indexing for
    """
    try:
        user_id = get_current_user()
        service = get_indexing_service_for_user(user_id)
        
        body = {"url": url, "type": "URL_UPDATED"}
        response = service.urlNotifications().publish(body=body).execute()
        
        lines = [
            f"# Ã¢ÂÂ Indexing Request Submitted\n",
            f"**URL:** {url}",
            "\n## Ã¢ÂÂ Ã¯Â¸Â Note",
            "The Indexing API works best for JobPosting and BroadcastEvent pages.",
            "For other pages, Google may not immediately act on this request."
        ]
        
        return "\n".join(lines)
    except HttpError as e:
        if e.resp.status == 403:
            return (
                "Ã¢ÂÂ **Permission Denied**\n\n"
                "The Indexing API requires:\n"
                "1. Enable the Indexing API in Google Cloud Console\n"
                "2. Verify site ownership in Search Console\n"
                "3. Works primarily for JobPosting/BroadcastEvent pages"
            )
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def export_analytics(
    site_url: str,
    days: int = 28,
    dimensions: str = "query",
    format: str = "csv",
    row_limit: int = 500
) -> str:
    """
    Export search analytics data to CSV or JSON.
    
    Args:
        site_url: The site URL
        days: Number of days (default: 28)
        dimensions: Dimensions to include (query, page, device, country, date)
        format: Export format - csv or json (default: csv)
        row_limit: Maximum rows (default: 500)
    """
    try:
        user_id = get_current_user()
        service = get_gsc_service_for_user(user_id)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": dimension_list,
            "rowLimit": min(row_limit, 25000)
        }
        
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No data to export for {site_url}"
        
        rows = response.get("rows", [])
        
        if format.lower() == "json":
            export_data = []
            for row in rows:
                item = {}
                for i, dim in enumerate(dimension_list):
                    item[dim] = row.get("keys", [])[i] if i < len(row.get("keys", [])) else ""
                item["clicks"] = row.get("clicks", 0)
                item["impressions"] = row.get("impressions", 0)
                item["ctr"] = round(row.get("ctr", 0) * 100, 2)
                item["position"] = round(row.get("position", 0), 1)
                export_data.append(item)
            
            return f"```json\n{json.dumps(export_data, indent=2)}\n```"
        
        else:
            csv_lines = []
            header = dimension_list + ["clicks", "impressions", "ctr", "position"]
            csv_lines.append(",".join(header))
            
            for row in rows:
                values = []
                for i, dim in enumerate(dimension_list):
                    val = row.get("keys", [])[i] if i < len(row.get("keys", [])) else ""
                    val = str(val).replace('"', '""')
                    if ',' in val or '"' in val:
                        val = f'"{val}"'
                    values.append(val)
                
                values.extend([
                    str(row.get("clicks", 0)),
                    str(row.get("impressions", 0)),
                    f"{row.get('ctr', 0) * 100:.2f}",
                    f"{row.get('position', 0):.1f}"
                ])
                csv_lines.append(",".join(values))
            
            return f"```csv\n" + "\n".join(csv_lines) + "\n```"
    
    except Exception as e:
        return f"Error: {str(e)}"


# =============================================================================
# MCP SSE ENDPOINTS
# =============================================================================

# Per-user SSE transport registry (shared between GET /sse and POST /messages handlers)
_user_sse_transports: dict = {}


@app.get("/mcp/{user_id}/sse")
async def mcp_sse_endpoint(request: Request, user_id: str):
    """SSE endpoint for MCP communication."""
    
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key. Please authenticate at /")
    
    set_current_user(user_id)
    
    sse = SseServerTransport(f"/mcp/{user_id}/messages")
    _user_sse_transports[user_id] = sse
    
    try:
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await mcp._mcp_server.run(
                streams[0],
                streams[1],
                mcp._mcp_server.create_initialization_options()
            )
    finally:
        _user_sse_transports.pop(user_id, None)


@app.post("/mcp/{user_id}/messages")
async def mcp_messages_endpoint(request: Request, user_id: str):
    """Message endpoint for MCP - forwards messages to the active SSE transport."""
    
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    set_current_user(user_id)
    
    sse = _user_sse_transports.get(user_id)
    if sse is None:
        raise HTTPException(status_code=503, detail="No active SSE session. Connect to /mcp/{user_id}/sse first.")
    
    await sse.handle_post_message(request.scope, request.receive, request._send)


# =============================================================================
# OAUTH DISCOVERY ENDPOINTS (required for MCP connector validation)
# =============================================================================

@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/{path:path}")
async def oauth_protected_resource(request: Request, path: str = ""):
    """OAuth protected resource metadata - server uses API key auth, not OAuth."""
    base_url = os.environ.get("BASE_URL", str(request.base_url).rstrip("/"))
    return JSONResponse({"resource": base_url, "authorization_servers": []})


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    """OAuth authorization server metadata - not using OAuth."""
    return JSONResponse({})


@app.post("/register")
async def register_dynamic_client(request: Request):
    """Dynamic client registration - not supported, using API key auth."""
    return JSONResponse(
        {"error": "not_supported", "error_description": "Use API key authentication"},
        status_code=400
    )


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/api/status/{user_id}")
async def user_status(user_id: str):
    """Check user authentication status."""
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "authenticated": True,
        "email": user["email"],
        "created": user["created_at"],
        "last_used": user["last_used"]
    }


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "=" * 60)
    print("Ã°ÂÂÂ GSC MCP Remote Server v2.0")
    print("=" * 60)
    print("\nRequired environment variables:")
    print("  GOOGLE_CLIENT_ID     - Google OAuth client ID")
    print("  GOOGLE_CLIENT_SECRET - Google OAuth client secret")
    print("\nOptional:")
    print("  GOOGLE_REDIRECT_URI  - Callback URL (default: http://localhost:8000/oauth/callback)")
    print("  BASE_URL             - Your server's public URL")
    print("  SECRET_KEY           - Session secret key")
    print("  DATABASE_PATH        - SQLite database path")
    print("\n" + "=" * 60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

