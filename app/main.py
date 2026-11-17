
from fastapi import FastAPI
from app.routers.auth import router as auth_router
from app.routers.resume import router as resume_router
from app.routers.users import router as users_router

app = FastAPI(
    title="AI Resume Parser & 2FA Onboarding",
    description="Resume parsing and secure onboarding APIs",
    version="1.0.0"
)

app.include_router(resume_router)
app.include_router(auth_router)
app.include_router(users_router)


@app.get("/")
async def root():
    return {"message": "Resume Onboarding API is running"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
