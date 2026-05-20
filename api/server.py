from main import app

# Vercel's Python runtime recognizes an ASGI application variable named `app`.
# Importing `app` from the project's `main.py` exposes the FastAPI instance
# directly to Vercel so it can serve requests.

# Expose `app` (already imported) — nothing else required.
