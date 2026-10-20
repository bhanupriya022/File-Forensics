# File Forensics

A web-based cybersecurity tool that examines uploaded files to detect mismatches between their filename extensions and actual file formats. Analysis is performed on real uploaded file contents — no hardcoded examples, no database.

---

## Features

| Feature | Description |
|---|---|
| **File Upload** | Drag-and-drop or browse · multiple files at once · up to 50 MB per file |
| **Actual Format Detection** | Reads magic bytes (file signatures) and content heuristics to determine the true file format |
| **Extension Mismatch Detection** | Compares the declared extension against the detected MIME type |
| **Risk Assessment** | Scores each file 0–100 (SAFE / LOW / MEDIUM / HIGH) based on format, disguise pattern, and mismatch |
| **Analysis Report** | Per-file report: detected format, MIME type, detection method, Shannon entropy, MD5 & SHA-256 hashes, timestamp |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3 (plain), Vanilla JavaScript |
| Backend | Python 3.10+ · Flask · Werkzeug |
| File Analysis | Pure Python — magic bytes, zipfile (stdlib), text heuristics |
| No database | All analysis is in-memory; temp files are deleted after analysis |

---

## Project Structure

```
File Forensics/
├── app.py           # Flask server — upload endpoint, routing
├── analyzer.py      # Core analysis engine (format detection, risk, hashes, entropy)
├── requirements.txt
├── README.md
└── static/
    ├── index.html   # Single-page UI
    ├── style.css    # Minimalist stylesheet
    └── script.js    # Frontend logic (drag-drop, fetch, rendering)
```

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# 1. Clone or download the project
cd "File Forensics"

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5000**

---

## How It Works

### Format Detection — `analyzer.py`

1. **Magic bytes**: The first 512 bytes of every file are compared against a built-in signature table of 40+ known formats (JPEG, PNG, PDF, PE, ELF, ZIP, DOCX, MP3, MP4, …).
2. **RIFF refinement**: RIFF containers (WAV, AVI, WebP) are further identified by bytes 8–12.
3. **ZIP refinement**: ZIP-based formats (DOCX, XLSX, PPTX, ODF, JAR) are distinguished by inspecting the ZIP entry list.
4. **Text heuristic**: If no binary signature matches and >85% of the header bytes are printable ASCII, the content is classified as text (HTML, XML, JSON, Python, Shell, CSV, CSS, JS, or plain text).

### Extension Mismatch Detection

Each known extension maps to one or more expected MIME types. After detection, the actual MIME type is checked against the expected set. Any deviation is flagged as a mismatch.

### Risk Scoring

| Factor | Score added |
|---|---|
| Extension mismatch | +50 |
| Detected type is an executable or script | +40 |
| Detected type is an archive or database | +20 |
| Dangerous disguise (e.g. EXE as PDF) | +10 |

Final score is capped at 100 and mapped to: **SAFE** (0–9) · **LOW** (10–29) · **MEDIUM** (30–59) · **HIGH** (60–100).

### File Security

- Uploaded files are saved to a system temp directory with a random UUID prefix.
- Each temp file is **deleted immediately** after analysis, regardless of success or failure.
- The server does not store any file content or metadata persistently.

---

## API

### `POST /api/analyze`

Upload one or more files for analysis.

**Request:** `multipart/form-data` with field `files` (multiple allowed).

**Response:**
```json
{
  "results": [
    {
      "filename": "document.pdf",
      "extension": ".pdf",
      "file_size": 204800,
      "file_size_human": "200.0 KB",
      "detected_mime": "application/pdf",
      "detected_label": "PDF Document",
      "detection_method": "magic_bytes",
      "expected_mimes": ["application/pdf"],
      "mismatch": false,
      "mismatch_detail": "Extension matches detected format",
      "risk": {
        "level": "SAFE",
        "score": 0,
        "reasons": ["No anomalies detected"]
      },
      "hashes": {
        "md5": "...",
        "sha256": "..."
      },
      "entropy": 6.82,
      "entropy_note": "High — file may be compressed ...",
      "analyzed_at": "2024-01-15T10:30:00Z"
    }
  ],
  "errors": []
}
```

### `GET /api/health`

```json
{ "status": "ok", "service": "File Forensics" }
```

---

## Supported Formats

**Images:** JPEG, PNG, GIF, BMP, ICO, TIFF, WebP, JPEG 2000  
**Documents:** PDF, DOC/XLS/PPT (OLE2), DOCX/XLSX/PPTX (OOXML), ODF  
**Audio:** MP3, FLAC, OGG, WAV, M4A  
**Video:** MP4, MOV, MKV, WebM, AVI  
**Archives:** ZIP, GZ, BZ2, XZ, 7Z, RAR, TAR  
**Executables:** PE (Windows), ELF (Linux), Mach-O (macOS)  
**Fonts:** TTF, OTF, WOFF, WOFF2  
**Text/Code:** Plain text, HTML, XML, JSON, Python, Shell, CSS, JavaScript, CSV  
**Other:** SQLite, PostScript, Java Class/JAR  

---

## License

MIT
