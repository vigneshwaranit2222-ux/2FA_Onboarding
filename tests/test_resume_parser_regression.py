from io import BytesIO

from docx import Document

from app.services.resume_parser import extract_resume_text, parse_resume


def test_existing_docx_resume_extraction_and_parsing_still_works() -> None:
    document = Document()
    document.add_paragraph("Ada Lovelace")
    document.add_paragraph("ada@example.com")
    document.add_paragraph("+919876543210")
    document.add_paragraph("Python FastAPI, 3 years experience")
    content = BytesIO()
    document.save(content)

    text = extract_resume_text(".docx", content.getvalue())
    parsed = parse_resume(text)

    assert parsed["full_name"] == "Ada Lovelace"
    assert parsed["email"] == "ada@example.com"
    assert parsed["phone"] == "+919876543210"
    assert "Python" in parsed["skills"]
