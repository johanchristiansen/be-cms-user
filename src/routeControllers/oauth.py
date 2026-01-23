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
    idToken = tokenResponse.get("id_token")
    # tokenResponse may not include 'userinfo'; fall back to explicit userinfo call
    userInfo = tokenResponse.get("userinfo") or oauth.keycloak.userinfo()
    # robust role extraction
    uRoles = []
    client_id = getattr(oauth.keycloak, "client_id", None)
    if isinstance(userInfo, dict):
        # resource_access -> client-specific roles
        try:
            if "resource_access" in userInfo and client_id in userInfo["resource_access"]:
                roles = userInfo["resource_access"][client_id].get("roles", [])
                uRoles = roles if isinstance(roles, list) else [roles]
            # realm_access -> realm-level roles
            elif "realm_access" in userInfo and "roles" in userInfo["realm_access"]:
                roles = userInfo["realm_access"]["roles"]
                uRoles = roles if isinstance(roles, list) else [roles]
            # direct roles array
            elif "roles" in userInfo:
                roles = userInfo["roles"]
                uRoles = roles if isinstance(roles, list) else [roles]
        except Exception:
            uRoles = []
    createUserSession(
        userId=userInfo.get("sub", ""),
        userName=userInfo.get("preferred_username", ""),
        email=userInfo.get("email", ""),
        roles=uRoles,
        idToken=idToken or "")
    return redirect('/')


@oauthPage.route("/logout")
def logout():
    user = getUserFromSession()
    idToken = user["idToken"] if not user is None else None
    clearUserSession()
    appConfig = getAppConfig()  # added
    post_logout = appConfig.postLogoutRedirectUri if getattr(appConfig, "postLogoutRedirectUri", None) else url_for("index", _external=True)
    if idToken:
        return redirect(str(oauth.keycloak.load_server_metadata().get('end_session_endpoint')) + "?" 
                        + urlencode(
                            {
                                "post_logout_redirect_uri": post_logout,
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