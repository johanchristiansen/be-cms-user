from fastapi import FastAPI, Depends
from app.auth.keycloack_auth import get_current_user
app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the CMS API"}

@app.get("/admin/content")
def protected_cms_data(user: dict = Depends(get_current_user)):
    # This route only works if a valid Keycloak token is provided
    return {
        "message": f"Hello {user.get('name')}, here is your private content.",
        "user_email": user.get("email")
    }