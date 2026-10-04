#type: ignore
import secrets
from flask import Flask, redirect, request, session, url_for
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt
from pyauth import Google  # replace with your actual module or put Google class here

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

REDIRECT_URI = "http://localhost:5000/callback"

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

google_auth = Google(CLIENT_ID, CLIENT_SECRET)

global_state=''
global_code_verifier=''
global_code_challenge=''
@app.route("/")
def index():
    global global_state
    global global_code_verifier
    global global_code_challenge

    url, state, code_verifier, code_challenge = google_auth.get_authorisation_url()
    global_state = state
    global_code_verifier = code_verifier
    global_code_challenge = code_challenge

    # Save state and code_verifier in session to verify later
    print(state, code_verifier, code_challenge)
    print(url)
    return url
@app.route("/callback")
def callback():
    # Validate state

    state = global_state
    code_verifier = global_code_verifier
    req_state = request.args.get('state')

    code = request.args.get('code')

    sub = google_auth.authorise_user(req_state, code, code_verifier)

    return sub



if __name__ == "__main__":
    app.run(debug=True)
