"""Health router stub.

NOTE: this is NOT the real /api/health contract — that is ported in Group 2.2.
For scaffold purposes it only confirms the app boots and routes resolve.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def root() -> dict[str, str]:
    return {"status": "scaffold-ok"}
