"""
Minimal Flask-compatible shim built on Python stdlib http.server.
Implements the exact Flask API surface used by Secure Lens AI.
"""

import json
import os
import re
import cgi
import io
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

__version__ = "3.1.0"

# ---------------------------------------------------------------------------
# Global request context (thread-local)
# ---------------------------------------------------------------------------
_request_ctx = threading.local()


class _RequestProxy:
    """Thread-local proxy to current request."""

    @property
    def _req(self):
        return getattr(_request_ctx, "request", None)

    @property
    def method(self):
        return self._req.method if self._req else "GET"

    @property
    def path(self):
        return self._req.path if self._req else "/"

    @property
    def headers(self):
        return self._req.headers if self._req else {}

    def get_json(self, force=False, silent=False):
        req = self._req
        if not req:
            return None
        try:
            ct = req.headers.get("Content-Type", "")
            if force or "json" in ct:
                length = int(req.headers.get("Content-Length", 0))
                if length > 0:
                    body = req.rfile.read(length)
                    req._body = body
                    return json.loads(body.decode("utf-8"))
            return None
        except Exception:
            if silent:
                return None
            raise

    @property
    def files(self):
        req = self._req
        if req and not hasattr(req, "_parsed_files"):
            req._parsed_files = _FileStorage()
            ct = req.headers.get("Content-Type", "")
            if "multipart/form-data" in ct:
                env = {
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": ct,
                    "CONTENT_LENGTH": req.headers.get("Content-Length", ""),
                }
                try:
                    fs = cgi.FieldStorage(
                        fp=req.rfile,
                        headers=req.headers,
                        environ=env,
                    )
                    req._parsed_files = _MultipartFiles(fs)
                except Exception as e:
                    print(f"[FLASK] Multipart parsing error: {e}")
                    pass
        return getattr(req, "_parsed_files", _FileStorage())

    @property
    def args(self):
        req = self._req
        if req:
            parsed = urlparse(req.full_path)
            return _Args(parse_qs(parsed.query, keep_blank_values=True))
        return _Args({})

    @property
    def data(self):
        req = self._req
        if req and hasattr(req, "_body"):
            return req._body
        return b""


class _Args:
    """Query parameter wrapper with Flask-compatible .get()."""

    def __init__(self, params):
        self._params = params

    def get(self, key, default=None, type=None):
        vals = self._params.get(key, [])
        if not vals:
            return default
        val = vals[0]
        if type is not None:
            try:
                return type(val)
            except (ValueError, TypeError):
                return default
        return val


class _FileStorage:
    """Empty file storage."""

    def __contains__(self, key):
        return False

    def __getitem__(self, key):
        raise KeyError(key)


class _MultipartFiles:
    """Parsed multipart files."""

    def __init__(self, form):
        self._form = form

    def __contains__(self, key):
        try:
            return key in self._form and hasattr(self._form[key], 'filename')
        except (KeyError, AttributeError):
            return False

    def __getitem__(self, key):
        try:
            item = self._form[key]
            if not hasattr(item, 'filename'):
                raise KeyError(key)
            return _UploadedFile(item)
        except (KeyError, AttributeError) as e:
            print(f"[FLASK] Error accessing file '{key}': {e}")
            raise KeyError(key)


class _UploadedFile:
    """Wraps a cgi.FieldStorage item to mimic werkzeug FileStorage."""

    def __init__(self, field):
        self._field = field
        self.filename = field.filename or ""
        # Read file data and handle potential issues
        try:
            # Seek to beginning in case it was read before
            if hasattr(field.file, 'seek'):
                field.file.seek(0)
            self._data = field.file.read()
            if not isinstance(self._data, bytes):
                self._data = self._data.encode('utf-8') if isinstance(self._data, str) else b''
        except Exception as e:
            print(f"[FLASK] Error reading file data: {e}")
            self._data = b''
        self._pos = 0

    def read(self, n=-1):
        if n == -1:
            data = self._data[self._pos:]
            self._pos = len(self._data)
            return data
        data = self._data[self._pos:self._pos + n]
        self._pos += len(data)
        return data

    def seek(self, offset, whence=0):
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        elif whence == 2:
            self._pos = len(self._data) + offset

    def tell(self):
        return self._pos

    def save(self, dst):
        if isinstance(dst, str):
            with open(dst, "wb") as f:
                f.write(self._data)
        else:
            dst.write(self._data)


# Singleton request proxy
request = _RequestProxy()


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

class Response:
    """Minimal Flask Response."""

    def __init__(self, data="", status=200, headers=None, content_type="text/html"):
        if isinstance(data, str):
            self.data = data.encode("utf-8")
        elif isinstance(data, bytes):
            self.data = data
        else:
            self.data = str(data).encode("utf-8")
        self.status_code = status
        self.headers = dict(headers or {})
        self.headers.setdefault("Content-Type", content_type)


def jsonify(*args, **kwargs):
    """Create a JSON Response."""
    if args and kwargs:
        raise TypeError("jsonify() takes either args or kwargs, not both")
    if len(args) == 1:
        data = args[0]
    elif args:
        data = list(args)
    else:
        data = kwargs
    body = json.dumps(data, default=str)
    return Response(body, content_type="application/json")


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

class Blueprint:
    """Flask Blueprint shim."""

    def __init__(self, name, import_name, url_prefix=""):
        self.name = name
        self.import_name = import_name
        self.url_prefix = url_prefix
        self._rules = []

    def route(self, rule, methods=None, **kwargs):
        def decorator(f):
            full_rule = self.url_prefix + rule
            self._rules.append((full_rule, methods or ["GET"], f))
            return f
        return decorator


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

class Flask:
    """Minimal Flask application."""

    def __init__(self, import_name, **kwargs):
        self.import_name = import_name
        self.config = _Config()
        self._rules = []
        self._blueprints = []
        self._error_handlers = {}
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._teardown_funcs = []
        self._extensions = {}

    def route(self, rule, methods=None, **kwargs):
        def decorator(f):
            self._rules.append((rule, methods or ["GET"], f))
            return f
        return decorator

    def register_blueprint(self, bp):
        self._blueprints.append(bp)
        for rule, methods, func in bp._rules:
            self._rules.append((rule, methods, func))

    def errorhandler(self, code):
        def decorator(f):
            self._error_handlers[code] = f
            return f
        return decorator

    def before_request(self, f):
        self._before_request_funcs.append(f)
        return f

    def after_request(self, f):
        self._after_request_funcs.append(f)
        return f

    def app_context(self):
        return _AppContext(self)

    def config_from_object(self, obj):
        self.config.from_object(obj)

    def _match_route(self, path, method):
        """Match a request path to a registered route."""
        for rule, methods, func in self._rules:
            if method.upper() not in [m.upper() for m in methods]:
                continue
            # Convert Flask route pattern to regex in a single pass
            # to avoid <name> inside already-replaced (?P<name>...) being
            # re-matched by the second substitution.
            def _replace_param(m):
                full = m.group(0)  # e.g. <int:analysis_id> or <name>
                if ":" in full:
                    # typed parameter, e.g. <int:analysis_id>
                    ptype, name = full[1:-1].split(":", 1)
                    if ptype == "int":
                        return f"(?P<{name}>\\d+)"
                    return f"(?P<{name}>[^/]+)"
                else:
                    name = full[1:-1]
                    return f"(?P<{name}>[^/]+)"
            pattern = re.sub(r"<[^>]+>", _replace_param, rule)
            pattern = f"^{pattern}$"
            try:
                m = re.match(pattern, path)
                if m:
                    return func, m.groupdict()
            except re.error:
                continue
        return None, {}

    def run(self, host="127.0.0.1", port=5000, debug=False, **kwargs):
        """Run the development server."""
        app = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self):
                parsed = urlparse(self.path)
                path = parsed.path
                method = self.command

                # CORS preflight
                if method == "OPTIONS":
                    self._send_cors_response(200, b"")
                    return

                # Store full path for query parsing
                self.full_path = self.path

                # Set thread-local request
                _request_ctx.request = self
                _request_ctx.request.method = method
                _request_ctx.request.path = path
                _request_ctx.request.full_path = self.path

                try:
                    # Match route
                    func, kwargs = app._match_route(path, method)
                    if func is None:
                        handler = app._error_handlers.get(404)
                        if handler:
                            result = handler(None)
                        else:
                            result = jsonify({"error": "Not found"}), 404
                    else:
                        # Convert int params
                        for k, v in kwargs.items():
                            try:
                                kwargs[k] = int(v)
                            except (ValueError, TypeError):
                                pass
                        result = func(**kwargs)

                    self._send_result(result)

                except Exception as e:
                    if debug:
                        import traceback
                        traceback.print_exc()
                    handler = app._error_handlers.get(500)
                    if handler:
                        result = handler(e)
                        self._send_result(result)
                    else:
                        self._send_cors_response(
                            500,
                            json.dumps({"error": str(e)}).encode(),
                            "application/json",
                        )
                finally:
                    _request_ctx.request = None

            def _send_result(self, result):
                """Send a Flask-style result (Response, tuple, or string)."""
                tuple_status = None
                if isinstance(result, tuple):
                    body_part = result[0]
                    tuple_status = result[1] if len(result) > 1 else None
                    headers = result[2] if len(result) > 2 else {}
                else:
                    body_part = result
                    headers = {}

                if isinstance(body_part, Response):
                    # Tuple status takes precedence over Response's default status
                    status = tuple_status if tuple_status is not None else body_part.status_code
                    ct = body_part.headers.get("Content-Type", "application/json")
                    extra_headers = body_part.headers
                    data = body_part.data
                elif isinstance(body_part, str):
                    status = tuple_status if tuple_status is not None else 200
                    ct = "text/html"
                    extra_headers = {}
                    data = body_part.encode()
                elif isinstance(body_part, dict):
                    status = tuple_status if tuple_status is not None else 200
                    ct = "application/json"
                    extra_headers = {}
                    data = json.dumps(body_part, default=str).encode()
                else:
                    status = tuple_status if tuple_status is not None else 200
                    ct = "application/json"
                    extra_headers = {}
                    data = body_part.data if hasattr(body_part, "data") else str(body_part).encode()

                self._send_cors_response(status, data, ct, {**extra_headers, **headers})

            def _send_cors_response(self, status, data, content_type="text/plain", extra_headers=None):
                """Send response with CORS headers."""
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))

                cors_origins = app.config.get("CORS_ORIGINS", ["*"])
                origin = self.headers.get("Origin", "")
                if "*" in cors_origins or origin in cors_origins:
                    self.send_header("Access-Control-Allow-Origin", origin or "*")
                elif cors_origins:
                    self.send_header("Access-Control-Allow-Origin", cors_origins[0])

                self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Access-Control-Allow-Credentials", "true")

                if extra_headers:
                    for k, v in extra_headers.items():
                        if k.lower() not in ("content-type", "content-length"):
                            self.send_header(k, v)

                self.end_headers()
                if data:
                    self.wfile.write(data)

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

            def do_PUT(self):
                self._handle()

            def do_DELETE(self):
                self._handle()

            def do_OPTIONS(self):
                self._handle()

            def log_message(self, format, *args):
                pass  # Suppress default logging

        from http.server import ThreadingHTTPServer

        server = ThreadingHTTPServer((host, port), Handler)
        print(f"\n{'='*60}")
        print("Secure Lens AI Backend Starting")
        print(f"{'='*60}")
        print(f"Host: {host}")
        print(f"Port: {port}")
        print(f"Debug: {debug}")
        print(f"Database: {app.config.get('SQLALCHEMY_DATABASE_URI', 'N/A')}")
        print(f"CORS Origins: {app.config.get('CORS_ORIGINS', [])}")
        print(f"{'='*60}\n")
        print("Demo credentials:")
        print("  Username: admin")
        print("  Password: admin123\n")

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
            server.shutdown()


class _Config(dict):
    """Flask-like config dict."""

    def from_object(self, obj):
        if isinstance(obj, type):
            obj = obj()
        for key in dir(obj):
            if key.isupper():
                self[key] = getattr(obj, key)

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


class _AppContext:
    """Minimal app context manager."""

    def __init__(self, app):
        self.app = app

    def __enter__(self):
        _request_ctx.app = self.app
        return self

    def __exit__(self, *args):
        _request_ctx.app = None
