"""Werkzeug utility functions shim."""

import os
import re


def secure_filename(filename):
    """Pass a filename and it will return a secure version of it."""
    if isinstance(filename, str):
        # Replace path separators
        for sep in (os.sep, os.altsep):
            if sep:
                filename = filename.replace(sep, "/")

        filename = filename.split("/")[-1]

        # Remove non-ascii
        filename = re.sub(r"[^\w\s\-.]", "", filename).strip()
        # Replace spaces
        filename = re.sub(r"[\s]+", "_", filename)
        # Remove leading dots/dashes
        filename = filename.lstrip(".-")

    return filename or "unnamed"
