import secrets
from authlib.integrations.requests_client.oauth2_session import OAuth2Session
from authlib.oauth2.rfc7636 import create_s256_code_challenge # type: ignore
REDIRECT_URI = 'http://localhost:5000/callback'


#Github does not have pkce support
class Github:
    """
    Manages the OAuth2 authentication flow with GitHub.

    This class facilitates obtaining an authorization URL to initiate the GitHub
    login process and subsequently authorizing the user by exchanging the
    authorization code for an access token and fetching user information.
    """
    def __init__(self, client_id:str, client_secret:str):
        """
        Initializes the GitHub OAuth client.

        Args:
            client_id (str): The Client ID of your GitHub OAuth application.
            client_secret (str): The Client Secret of your GitHub OAuth application.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = 'read:user'


    def get_authorisation_url(self) -> tuple[str, str]:
        """
        Generates the GitHub OAuth2 authorization URL and a state parameter.

        The state parameter is used to prevent Cross-Site Request Forgery (CSRF) attacks.
        The user should be redirected to the generated URL to authorize the application.

        Returns:
            tuple[str, str]: A tuple containing:
                - The authorization URL (str) to redirect the user to.
                - The state parameter (str) which should be stored and verified during the callback.
        """
        client = OAuth2Session(self.client_id, self.client_secret, scope=self.scope)
        authorisation_endpoint='https://github.com/login/oauth/authorize'
        authorisation_url_link, state = client.create_authorization_url(authorisation_endpoint) # type: ignore
        return authorisation_url_link, state # type: ignore

    def authorise_user(self, authorisation_url:str) -> str:
        """
        Exchanges the authorization response URL (containing the code) for an access token
        and fetches the authenticated user's GitHub ID.

        This method should be called after the user has been redirected back from GitHub
        to the application's callback URL.

        Args:
            authorisation_url (str): The full callback URL received from GitHub,
                                     which includes the authorization `code` and `state`.

        Returns:
            str: The GitHub user's ID as a string.
        """
        token_endpoint = 'https://github.com/login/oauth/access_token'
        client = OAuth2Session(self.client_id, self.client_secret, scope=self.scope)
        token = client.fetch_token(token_endpoint, authorization_response=authorisation_url) # type: ignore
        print(token) # type: ignore
        resp = client.get('https://api.github.com/user')
        user_info=resp.json()
        print(user_info)
        return str(user_info['id']) # type: ignore

class Google:
    """
    Manages the OAuth2 authentication flow with Google, including PKCE (Proof Key for Code Exchange).

    This class facilitates obtaining an authorization URL to initiate the Google
    login process with PKCE and subsequently authorizing the user by exchanging
    the authorization code (along with the code verifier) for an access token
    and fetching user information.
    """
    def __init__(self, client_id:str, client_secret:str):
        """
        Initializes the Google OAuth client.

        Args:
            client_id (str): The Client ID of your Google OAuth 2.0 application.
            client_secret (str): The Client Secret of your Google OAuth 2.0 application.
        """
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth"
        token_endpoint="https://oauth2.googleapis.com/token"

        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_endpoint=authorization_endpoint
        self.token_endpoint = token_endpoint
        self.client = OAuth2Session(client_id, client_secret, scope="openid")

    def get_authorisation_url(self) -> tuple[str,str,str,str]:
        """
        Generates the Google OAuth2 authorization URL along with PKCE parameters (code_verifier,
        code_challenge) and a state parameter.

        The user should be redirected to the generated URL. The `code_verifier` should be
        stored (e.g., in the session) to be used later when exchanging the authorization code.

        Returns:
            tuple[str,str,str,str]: A tuple containing:
                - The authorization URL (str) to redirect the user to.
                - The state parameter (str) for CSRF protection.
                - The PKCE code verifier (str).
                - The PKCE code challenge (str) derived from the verifier.
        """
        code_verifier = secrets.token_urlsafe(48)
        code_challenge:str = create_s256_code_challenge(code_verifier) # type: ignore
        state = secrets.token_urlsafe(32)

        authorisation_url_link, state = self.client.create_authorization_url(url=self.authorization_endpoint, # type: ignore
                                                                                   state=state,
                                                                                   code_challenge=code_challenge,
                                                                                   code_challenge_method='S256', #Only S256 is supported, but included just to be explicit
                                                                                   redirect_uri=REDIRECT_URI,
                                                                                   # prompt='select_account' #COMMENT DURING PRODUCTION. uncomment if u need to reenter the email everytime u run the app

                                                                                   )

        return authorisation_url_link, state, code_verifier,code_challenge # type: ignore

    def authorise_user(self, state:str, code:str, code_verifier:str) -> str: # type: ignore
        """
        Exchanges the authorization code for an access token using the provided state and
        PKCE code verifier, then fetches the authenticated user's 'sub' (subject) identifier
        from Google's userinfo endpoint.

        This method should be called after the user has been redirected back from Google
        to the application's callback URL.

        Args:
            state (str): The state parameter received in the callback URL from Google.
                         This must match the state generated by `get_authorisation_url`.
            code (str): The authorization code received from Google in the callback URL.
            code_verifier (str): The PKCE code verifier generated by `get_authorisation_url`
                                 and stored by the application.

        Returns:
            str: The user's 'sub' (subject) identifier from Google, which is a unique ID for the user.
        """
        client = OAuth2Session(client_id=self.client_id, # type: ignore
                               client_secret=self.client_secret, # type: ignore
                               scope="openid",
                               redirect_uri='http://localhost:5000/callback',
                               state=state,
                               token_endpoint_auth_method='client_secret_post',
                               )
        #token contains access_token, expiry etc. but we dont need to use it as we are
        # only using it to purely authenticate users. We would use if we need to access other google services of the user
        token = client.fetch_token(self.token_endpoint, code=code, code_verifier=code_verifier,) # type: ignore
        resp = client.get('https://openidconnect.googleapis.com/v1/userinfo')

        # user_info contains sub key and picture key
        user_info = resp.json()
        return user_info['sub']