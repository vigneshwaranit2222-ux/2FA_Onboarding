
import logging
from pathlib import Path
from uuid import uuid4

from fastapi import (
    APIRouter,
    UploadFile,
    File,
    Depends,
    HTTPException,
)
from app.core.security import get_current_user
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.resume import UserResume
from app.models.user import User
from app.schemas.resume import ResumeParseResponse
from app.services.resume_parser import (
    extract_resume_text,
    parse_resume,
)


# Logging configuration
logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/resume",
    tags=["Resume"]
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 5 * 1024 * 1024


@router.post(
    "/parse",
    response_model=ResumeParseResponse
)
async def parse_uploaded_resume(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    file_path = None

    try:
        # 1. Validate filename
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is required"
            )

        # 2. Validate file extension
        extension = Path(file.filename).suffix.lower()

        if extension not in [".pdf", ".docx"]:
            raise HTTPException(
                status_code=400,
                detail="Only PDF and DOCX files are allowed"
            )

        # 3. Read uploaded file
        file_bytes = await file.read()

        if not file_bytes:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty"
            )

        # 4. Validate file size
        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Maximum file size is 5 MB"
            )

        # 5. Generate unique filename
        saved_filename = f"{uuid4().hex}{extension}"

        file_path = UPLOAD_DIR / saved_filename

        # 6. Extract resume text
        text = extract_resume_text(
            extension,
            file_bytes
        )

        if not text or not text.strip():
            raise HTTPException(
                status_code=422,
                detail="No readable text found in resume"
            )

        # 7. Parse resume information
        extracted_data = parse_resume(text)

        # 8. Save uploaded file
        file_path.write_bytes(file_bytes)

        # 9. Create database record
        resume = UserResume(
            user_id=current_user.id,
            file_name=file.filename,
            file_path=str(file_path),
            extracted_text=text,
            extracted_data=extracted_data,
        )

        db.add(resume)

        # 10. Commit database transaction
        await db.commit()

        await db.refresh(resume)

        # 11. Return response
        return ResumeParseResponse(
            resume_id=resume.id,
            **extracted_data,
            message="Resume parsed successfully"
        )

    except HTTPException:
        raise

    except Exception:
        # Print the complete error in backend terminal
        logger.exception("Resume processing failed")

        # Rollback database transaction
        await db.rollback()

        # Remove uploaded file if processing failed
        if file_path and file_path.exists():
            file_path.unlink()

        raise HTTPException(
            status_code=500,
            detail="Resume processing failed. Check backend logs."
        )

    finally:
        await file.close()
