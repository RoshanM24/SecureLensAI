"""Flask-CORS shim. CORS headers are handled inside the Flask shim's Handler."""


class CORS:
    """No-op CORS extension. The Flask shim handles CORS headers directly."""

    def __init__(self, app=None, **kwargs):
        if app:
            self.init_app(app, **kwargs)

    def init_app(self, app, **kwargs):
        origins = kwargs.get("origins", app.config.get("CORS_ORIGINS", ["*"]))
        if isinstance(origins, str):
            origins = [origins]
        app.config["CORS_ORIGINS"] = origins
