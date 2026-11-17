
import re
import io

import pdfplumber
from docx import Document


def extract_text_from_pdf(file_bytes: bytes) -> str:

    text = []

    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:

        for page in pdf.pages:

            page_text = page.extract_text()

            if page_text:
                text.append(page_text)

    return "\n".join(text)


def extract_text_from_docx(file_bytes: bytes) -> str:

    document = Document(io.BytesIO(file_bytes))

    paragraphs = [
        paragraph.text
        for paragraph in document.paragraphs
        if paragraph.text.strip()
    ]

    return "\n".join(paragraphs)


def extract_resume_text(
    filename: str,
    file_bytes: bytes
) -> str:

    extension = filename.lower().rsplit(".", 1)[-1]

    if extension == "pdf":
        return extract_text_from_pdf(file_bytes)

    elif extension == "docx":
        return extract_text_from_docx(file_bytes)

    else:
        raise ValueError("Unsupported resume format")


def extract_email(text: str):

    pattern = r'[\w.+-]+@[\w-]+\.[\w.-]+'

    match = re.search(pattern, text)

    return match.group(0) if match else None


def extract_phone(text: str):

    pattern = r'(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)'

    match = re.search(pattern, text)

    return match.group(0) if match else None


def extract_name(text: str):

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        return None

    return lines[0][:150]


def extract_skills(text: str):

    known_skills = [
        "Python",
        "FastAPI",
        "Django",
        "Flask",
        "Java",
        "JavaScript",
        "React",
        "SQL",
        "PostgreSQL",
        "MySQL",
        "Machine Learning",
        "Deep Learning",
        "LangChain",
        "LangGraph",
        "RAG",
        "Docker",
        "Git",
    ]

    found_skills = []

    for skill in known_skills:

        pattern = (
            r"(?<![a-zA-Z0-9])"
            + re.escape(skill)
            + r"(?![a-zA-Z0-9])"
        )

        if re.search(pattern, text, re.IGNORECASE):
            found_skills.append(skill)

    return found_skills


def extract_experience(text: str):

    pattern = (
        r'(\d+(?:\.\d+)?)\s*'
        r'(years?|yrs?|months?)\s+'
        r'(?:of\s+)?experience'
    )

    match = re.search(pattern, text, re.IGNORECASE)

    return match.group(0) if match else None


def parse_resume(text: str):

    return {
        "full_name": extract_name(text),
        "email": extract_email(text),
        "phone": extract_phone(text),
        "skills": extract_skills(text),
        "experience": extract_experience(text),
    }
