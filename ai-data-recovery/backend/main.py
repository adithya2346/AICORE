"""
FastAPI Central Orchestration Server for AI-Assisted Data Recovery System.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from backend.config import settings
from backend.database.database import engine, Base
from backend.api.recovery import router as recovery_router
from backend.api.status import router as status_router
from backend.api.results import router as results_router

# Create database tables if they do not exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Real AI/ML-assisted forensic recovery and fragment reconstruction platform."
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(recovery_router)
app.include_router(status_router)
app.include_router(results_router)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

# Static files for web dashboard
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/", response_class=FileResponse)
def serve_dashboard():
    dashboard_path = static_dir / "index.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return {
        "system": settings.app_name,
        "version": settings.version,
        "status": "online"
    }

@app.get("/dashboard", response_class=FileResponse)
def serve_dashboard_alias():
    return FileResponse(static_dir / "index.html")

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
