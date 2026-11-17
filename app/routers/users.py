from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database.session import get_db
from app.models.resume import UserResume
from app.models.user import User
from app.schemas.user import (
    ResumeDetail,
    ResumeExtractedDataUpdate,
    ResumeItem,
)


router = APIRouter(prefix="/api/v1/users", tags=["Users"])
UPLOAD_ROOT = Path("uploads").resolve()


@router.get(
    "/me/resumes",
    response_model=list[ResumeItem],
    summary="List the authenticated user's resumes",
    responses={401: {"description": "Authentication required"}},
)
async def list_my_resumes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ResumeItem]:
    result = await db.scalars(
        select(UserResume)
        .where(UserResume.user_id == current_user.id)
        .order_by(UserResume.created_at.desc())
    )
    return [ResumeItem.model_validate(resume) for resume in result.all()]


@router.get(
    "/me/resumes/{resume_id}",
    response_model=ResumeDetail,
    summary="View an owned resume and extracted text",
    responses={401: {"description": "Authentication required"}, 404: {"description": "Resume not found"}},
)
async def get_my_resume(
    resume_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResumeDetail:
    resume = await db.scalar(
        select(UserResume).where(
            UserResume.id == resume_id,
            UserResume.user_id == current_user.id,
        )
    )
    if resume is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume not found",
        )
    return ResumeDetail.model_validate(resume)


@router.patch(
    "/me/resumes/{resume_id}",
    response_model=ResumeDetail,
    summary="Correct extracted resume fields",
    description="Updates only the extracted candidate fields for a resume owned by the authenticated user.",
    responses={
        200: {"description": "Extracted data updated"},
        401: {"description": "Authentication required"},
        404: {"description": "Resume not found"},
    },
)
async def correct_my_resume(
    resume_id: int,
    corrections: ResumeExtractedDataUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ResumeDetail:
    resume = await db.scalar(
        select(UserResume).where(
            UserResume.id == resume_id,
            UserResume.user_id == current_user.id,
        )
    )
    if resume is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume not found",
        )

    updated_data = dict(resume.extracted_data or {})
    for field in corrections.model_fields_set:
        value = getattr(corrections, field)
        updated_data[field] = str(value) if field == "email" and value is not None else value
    resume.extracted_data = updated_data
    try:
        await db.commit()
        await db.refresh(resume)
    except Exception:
        await db.rollback()
        raise
    return ResumeDetail.model_validate(resume)


@router.get(
    "/me/resumes/{resume_id}/file",
    response_class=FileResponse,
    summary="Download an owned resume file",
    responses={401: {"description": "Authentication required"}, 404: {"description": "Resume not found"}},
)
async def download_my_resume(
    resume_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    resume = await db.scalar(
        select(UserResume).where(
            UserResume.id == resume_id,
            UserResume.user_id == current_user.id,
        )
    )
    if resume is None or not resume.file_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume not found",
        )

    path = Path(resume.file_path).resolve()
    if not path.is_relative_to(UPLOAD_ROOT) or not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume file not found",
        )
    extension = path.suffix.lower()
    media_type = (
        "application/pdf"
        if extension == ".pdf"
        else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    return FileResponse(
        path,
        media_type=media_type,
        filename=Path(resume.file_name).name,
    )
