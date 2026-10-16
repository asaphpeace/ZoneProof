from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.detection_coverage import DetectionCoverageEdgeOut
from app.services.detection_coverage_service import compute_detection_coverage

router = APIRouter(prefix="/detection-coverage", tags=["detection-coverage"])


@router.get("", response_model=list[DetectionCoverageEdgeOut])
async def get_detection_coverage(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Real per-attack-path detection coverage for the current tenant —
    see detection_coverage_service.py for how each verdict is derived.
    Returns an empty list (not an error) if no privilege-escalation paths
    have been discovered yet, same convention as GET /graph."""
    data = await compute_detection_coverage(db, user.tenant_id)
    return [DetectionCoverageEdgeOut(**row) for row in data]
