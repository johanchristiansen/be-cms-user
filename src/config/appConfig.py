from dataclasses import dataclass, field
import json
import os


@dataclass
class AppConfig:
    oauthAppClientId: str = field(default="")
    oauthAppClientSecret: str = field(default="")
    oauthProviderDiscoveryUrl: str = field(default="")
    flaskSecret: str = field(default="")
    postLogoutRedirectUri: str = field(default="")

jsonConfig: AppConfig = None


def loadAppConfig(fName="config/config.json") -> AppConfig:
    global jsonConfig
    # Jika file ada (lokal), gunakan file
    if os.path.exists(fName):
        with open(fName) as f:
            data = json.load(f)
            jsonConfig = AppConfig(**data)
    else:
        # Jika tidak ada (Railway/Production), gunakan Env Vars
        jsonConfig = AppConfig(
            oauthAppClientId=os.getenv("OAUTH_CLIENT_ID"),
            oauthAppClientSecret=os.getenv("OAUTH_CLIENT_SECRET"),
            oauthProviderDiscoveryUrl=os.getenv("OAUTH_PROVIDER_URL"),
            flaskSecret=os.getenv("FLASK_SECRET"),
            postLogoutRedirectUri=os.getenv("POST_LOGOUT_REDIRECT_URI")
        )
    return jsonConfig


def getAppConfig() -> AppConfig:
    return jsonConfig