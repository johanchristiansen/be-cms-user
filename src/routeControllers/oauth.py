from urllib.parse import quote_plus, urlencode
from flask import Blueprint, redirect, url_for, current_app, session, abort, request, jsonify
import requests
from src.config.appConfig import getAppConfig
from src.security.user import createUserSession, clearUserSession, getUserFromSession
from authlib.integrations.flask_client import OAuth

oauthPage = Blueprint('oauth', __name__,
                      template_folder='templates')

oauth = None


def initOauthClient():
    global oauth
    appConfig = getAppConfig()
    oauth = OAuth(current_app)
    oauth.register(
        "keycloak",
        client_id=appConfig.oauthAppClientId,
        client_secret=appConfig.oauthAppClientSecret,
        client_kwargs={
            "scope": "openid profile email roles",
            # 'code_challenge_method': 'S256'  # enable PKCE
        },
        server_metadata_url=appConfig.oauthProviderDiscoveryUrl,
    )


@oauthPage.route("/login")
def login():
    # check if session already present
    if "user" in session:
        abort(404)
    return oauth.keycloak.authorize_redirect(redirect_uri=url_for(".callback", _external=True))


@oauthPage.route("/login/callback")
def callback():
    tokenResponse = oauth.keycloak.authorize_access_token()
    idToken = tokenResponse["id_token"]
    userInfo = tokenResponse["userinfo"]
    # if roles are not included in id token, call user info endpoint explicitly 
    # userInfo = oauth.keycloak.userinfo()
    uRoles = []
    if oauth.keycloak.client_id in userInfo['resource_access']:
        uRoles = userInfo['resource_access'][oauth.keycloak.client_id]["roles"]
    if not (isinstance(uRoles, list)):
        uRoles = [uRoles]
    createUserSession(
        userId=userInfo["sub"], userName=userInfo["preferred_username"], email=userInfo["email"], roles=uRoles, idToken=idToken)
    return redirect('/')


@oauthPage.route("/logout")
def logout():
    # https://stackoverflow.com/a/72011979/2746323
    user = getUserFromSession()
    idToken = user["idToken"] if not user is None else None
    clearUserSession()
    if idToken:
        return redirect(str(oauth.keycloak.load_server_metadata().get('end_session_endpoint')) + "?"
                        + urlencode(
                            {
                                "post_logout_redirect_uri": url_for("index", _external=True),
                                "id_token_hint": idToken
                            },
                            quote_via=quote_plus))
    else:
        return redirect(url_for("index"))
    
@oauthPage.route("/token", methods=["POST"])
def token_by_password():
    """
    POST JSON: { "username": "...", "password": "..." }
    Returns the token response from Keycloak (access_token, refresh_token, id_token, expires_in, ...)
    """
    if oauth is None:
        abort(500, "OAuth client not initialized")
    data = request.get_json(force=True, silent=True)
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username and password required"}), 400
    username = data["username"]
    password = data["password"]
    try:
        metadata = oauth.keycloak.load_server_metadata()
        token_url = metadata.get("token_endpoint")
        if not token_url:
            return jsonify({"error": "token_endpoint_not_found"}), 500
        appConfig = getAppConfig()
        # Use HTTP Basic auth for client authentication
        resp = requests.post(
            token_url,
            data={
                "grant_type": "password",
                "username": username,
                "password": password,
            },
            auth=(appConfig.oauthAppClientId, appConfig.oauthAppClientSecret),
            timeout=5
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"error": "token_request_failed", "details": str(ex)}), 400


@oauthPage.route("/token/validate", methods=["POST"])
def validate_token():
    """
    POST JSON: { "token": "..." }
    Uses Keycloak introspection endpoint to validate the token.
    """
    if oauth is None:
        abort(500, "OAuth client not initialized")
    data = request.get_json(force=True, silent=True)
    if not data or "token" not in data:
        return jsonify({"error": "token required"}), 400
    token = data["token"]
    appConfig = getAppConfig()
    metadata = oauth.keycloak.load_server_metadata()
    introspect_url = metadata.get("introspection_endpoint")
    if not introspect_url:
        return jsonify({"error": "introspection_endpoint not available"}), 500
    try:
        resp = requests.post(
            introspect_url,
            data={"token": token},
            auth=(appConfig.oauthAppClientId, appConfig.oauthAppClientSecret),
            timeout=5
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"error": "introspection_failed", "details": str(ex)}), 500