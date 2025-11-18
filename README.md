Flask MFA demo (TOTP) - Ready for Render
========================================

How to run locally:
1. python3 -m venv venv
2. source venv/bin/activate
3. pip install -r requirements.txt
4. export FLASK_ENV=development
5. flask run --host=0.0.0.0 --port=5000
   or: python app.py

Deploy on Render:
- Connect repo or upload this ZIP in Render and set build command to:
  pip install -r requirements.txt
- Start command:
  gunicorn --bind 0.0.0.0:$PORT app:app

Notes:
- This project uses an in-memory dict for users (demo only). Use a DB for production.
- Replace app.secret_key with a secure random value in production.