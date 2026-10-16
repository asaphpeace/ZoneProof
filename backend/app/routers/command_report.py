"""
Sentinel Command report — Coverage Map plan Phase 10. Reuses V1's existing
pdf_report feature gate (same plan tiers that unlock the DMARC-only report
already unlock this one; it is the same "download report" concept, just
covering more of the product) and the same Playwright rendering pipeline.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import Tenant, User
from app.routers.auth import get_current_user
from app.schemas.command_report import CommandReportDataOut
from app.services.command_report_service import assemble_command_report, render_command_report_pdf
from app.services.plan_limits import require_feature

router = APIRouter(tags=["command-report"])


@router.get("/command-report-data", response_model=CommandReportDataOut)
async def get_command_report_data(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant = (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one()
    return await assemble_command_report(db, tenant, user)


@router.get("/command-report-pdf")
async def get_command_report_pdf(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant = (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one()
    require_feature(tenant, "pdf_report")

    report = await assemble_command_report(db, tenant, user)
    pdf_bytes = await render_command_report_pdf(report)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinel-command-report-{report.generated_at[:10]}.pdf"'},
    )
