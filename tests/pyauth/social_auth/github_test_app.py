#type: ignore

import secrets
from flask import Flask, redirect, request, session, url_for
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt
from pyauth import Github

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

REDIRECT_URI = "http://localhost:5000/callback"

CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")

github_auth = Github(CLIENT_ID, CLIENT_SECRET)

global_state=''
@app.route("/")
def index():
    global global_state

    authorisation_url_link, state = github_auth.get_authorisation_url()
    global_state = state

    # Save state and code_verifier in session to verify later
    print(authorisation_url_link)
    return authorisation_url_link

@app.route("/callback")
def callback():
    url = request.url
    state = request.args.get('state')
    # important verify the state make sure they same, prevent csrf
    if global_state == state:
        print(state)
        token = github_auth.authorise_user(url)
        print(token)
        return token
    return 'noob'



if __name__ == "__main__":
    app.run(debug=True)
