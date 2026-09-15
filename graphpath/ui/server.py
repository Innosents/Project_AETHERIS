"""
Project AETHERIS - Asynchronous Web UI Server Runner.
"""

import threading
from flask import Flask
from flask_cors import CORS
from graphpath.ui.routes import ui_bp


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)
    app.register_blueprint(ui_bp)
    return app


def start_ui_async(port: int = 8080) -> threading.Thread:
    """Spawns Flask web server on a background daemon thread."""
    app = create_app()

    def _run():
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

    server_thread = threading.Thread(target=_run, daemon=True, name="GraphPath-WebServer")
    server_thread.start()
    return server_thread