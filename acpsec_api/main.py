"""FastAPI application instance for acpsec_api.

Pure scaffold: creates the app, wires CORS middleware (origins filled in
Group 2.8), and mounts the health router stub. Does NOT yet import the
acpsec scoring/model/catalogue/onchain modules — that happens in Group 2.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from acpsec_api.routers import health, leaderboard, score

app = FastAPI(
    title="ACP-SEC API",
    description="FastAPI backend for the ACP-SEC dashboard/app (scaffold).",
    version="0.5.0",
)

# CORS stub — allow_origins populated in Group 2.8 once the frontend origin
# is known. Left empty for now so nothing is silently permitted.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(score.router)
app.include_router(leaderboard.router)
