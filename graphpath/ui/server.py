import os
import sys
import threading
from flask import Flask, make_response, send_from_directory

# Force absolute project root registration to prevent ModuleNotFoundError across threads
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ui.routes import api_bp  
from ui.auth_middleware import session_manager, is_loopback_client  # Import session manager & loopback checker

try:
    from core.path_utils import get_resource_path
    STATIC_DIR = str(get_resource_path(os.path.join("ui", "static")))
except ImportError:
    STATIC_DIR = os.path.join(BASE_DIR, "ui", "static")

import logging
from flask import request
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Register the Blueprint to expose /api/topology endpoints
app.register_blueprint(api_bp)

@app.route("/")
def index():
    res = make_response(send_from_directory(STATIC_DIR, "index.html"))
    
    # Inject persistent administrative credential for verified local host clients
    # Remote LAN / WAN clients MUST provide credentials via header or cookie and are not auto-granted
    remote_ip = request.remote_addr or ""
    if is_loopback_client(remote_ip):
        active_credential = session_manager._active_token
        res.set_cookie("fa_token", active_credential, httponly=False, samesite="Lax", path="/")
    return res

@app.route("/<path:filename>")
def static_files(filename):
    """Corrected route path mapping to safely forward static browser payloads."""
    res = make_response(send_from_directory(STATIC_DIR, filename))
    remote_ip = request.remote_addr or ""
    if is_loopback_client(remote_ip) and filename in ("index.html", "presentation.html"):
        active_credential = session_manager._active_token
        res.set_cookie("fa_token", active_credential, httponly=False, samesite="Lax", path="/")
    return res

def start_ui_async(host: str = "", port: int = 0) -> None:
    """
    Spawns the Flask web interface server within a dedicated background thread.
    Binds securely to localhost (127.0.0.1) by default to prevent exposure on customer LANs.
    """
    bind_host = host or os.getenv("GRAPHPATH_HOST", "127.0.0.1")
    bind_port = port or int(os.getenv("GRAPHPATH_PORT", "8080"))

    def _run_server():
        # Disable the automatic reloader to prevent spawning duplicate background engines
        app.run(host=bind_host, port=bind_port, debug=False, use_reloader=False)

    server_thread = threading.Thread(target=_run_server, daemon=True)
    server_thread.start()
    print(f"[UI Server] Secure local interface initialized on http://{bind_host}:{bind_port}")

if __name__ == "__main__":
    h = os.getenv("GRAPHPATH_HOST", "0.0.0.0" if os.getenv("DOCKER_CONTAINER") else "127.0.0.1")
    p = int(os.getenv("GRAPHPATH_PORT", "5000" if os.getenv("DOCKER_CONTAINER") else "8080"))
    app.run(host=h, port=p)