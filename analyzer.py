"""
File format detection via magic bytes and content analysis.
No database — all signatures are defined inline.
"""

import os
import math
import struct
import hashlib
from datetime import datetime


# ---------------------------------------------------------------------------
# Magic-byte signature table
# Each entry: (offset, bytes_pattern, mime_type, label)
# ---------------------------------------------------------------------------
SIGNATURES = [
    # Images
    (0, b'\xff\xd8\xff',               'image/jpeg',       'JPEG Image'),
    (0, b'\x89PNG\r\n\x1a\n',         'image/png',        'PNG Image'),
    (0, b'GIF87a',                     'image/gif',        'GIF Image'),
    (0, b'GIF89a',                     'image/gif',        'GIF Image'),
    (0, b'BM',                         'image/bmp',        'BMP Image'),
    (0, b'\x00\x00\x01\x00',          'image/x-icon',     'ICO Icon'),
    (0, b'RIFF',                       None,               'RIFF Container'),   # refined below
    (0, b'\x49\x49\x2a\x00',          'image/tiff',       'TIFF Image (LE)'),
    (0, b'\x4d\x4d\x00\x2a',          'image/tiff',       'TIFF Image (BE)'),
    (0, b'\x00\x00\x00\x0cjP  ',      'image/jp2',        'JPEG 2000'),

    # Documents
    (0, b'%PDF',                       'application/pdf',  'PDF Document'),
    (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'application/msoffice', 'MS Office / OLE2 Document'),
    (0, b'PK\x03\x04',                'application/zip',  'ZIP / OOXML / ODF'),  # refined below

    # Audio / Video
    (0, b'ID3',                        'audio/mpeg',       'MP3 Audio (ID3)'),
    (0, b'\xff\xfb',                   'audio/mpeg',       'MP3 Audio'),
    (0, b'\xff\xf3',                   'audio/mpeg',       'MP3 Audio'),
    (0, b'\xff\xf2',                   'audio/mpeg',       'MP3 Audio'),
    (0, b'fLaC',                       'audio/flac',       'FLAC Audio'),
    (0, b'OggS',                       'audio/ogg',        'OGG Audio/Video'),
    (4, b'ftyp',                       'video/mp4',        'MP4 / M4A / MOV'),
    (0, b'\x1a\x45\xdf\xa3',          'video/webm',       'WebM / MKV'),

    # Archives
    (0, b'\x1f\x8b',                   'application/gzip', 'GZIP Archive'),
    (0, b'BZh',                        'application/x-bzip2', 'BZIP2 Archive'),
    (0, b'\xfd7zXZ\x00',              'application/x-xz', 'XZ Archive'),
    (0, b'7z\xbc\xaf\x27\x1c',        'application/x-7z-compressed', '7-Zip Archive'),
    (0, b'Rar!\x1a\x07\x00',          'application/x-rar', 'RAR Archive'),
    (0, b'Rar!\x1a\x07\x01\x00',      'application/x-rar', 'RAR5 Archive'),
    (0, b'\xca\xfe\xba\xbe',          'application/java-archive', 'Java Class / Universal Binary'),

    # Executables
    (0, b'MZ',                         'application/x-msdownload', 'Windows PE Executable'),
    (0, b'\x7fELF',                    'application/x-elf', 'ELF Executable (Linux/Unix)'),
    (0, b'\xfe\xed\xfa\xce',          'application/x-mach-binary', 'Mach-O Executable (32-bit)'),
    (0, b'\xfe\xed\xfa\xcf',          'application/x-mach-binary', 'Mach-O Executable (64-bit)'),
    (0, b'\xce\xfa\xed\xfe',          'application/x-mach-binary', 'Mach-O Executable (32-bit LE)'),
    (0, b'\xcf\xfa\xed\xfe',          'application/x-mach-binary', 'Mach-O Executable (64-bit LE)'),

    # Fonts
    (0, b'wOFF',                       'font/woff',        'WOFF Font'),
    (0, b'wOF2',                       'font/woff2',       'WOFF2 Font'),
    (0, b'\x00\x01\x00\x00\x00',      'font/ttf',         'TrueType Font'),
    (0, b'OTTO',                       'font/otf',         'OpenType Font'),

    # Misc
    (0, b'SQLite format 3\x00',        'application/x-sqlite3', 'SQLite Database'),
    (0, b'\x50\x4b\x05\x06',          'application/zip',  'Empty ZIP'),
    (0, b'\x25\x21',                   'application/postscript', 'PostScript'),
    (257, b'ustar\x00',               'application/x-tar', 'TAR Archive'),
    (257, b'ustar  \x00',             'application/x-tar', 'TAR Archive (GNU)'),
]

# Extension → expected mime-type groups
EXTENSION_MAP = {
    # Images
    '.jpg':  ['image/jpeg'],
    '.jpeg': ['image/jpeg'],
    '.png':  ['image/png'],
    '.gif':  ['image/gif'],
    '.bmp':  ['image/bmp'],
    '.ico':  ['image/x-icon'],
    '.tif':  ['image/tiff'],
    '.tiff': ['image/tiff'],
    '.webp': ['image/webp'],
    '.jp2':  ['image/jp2'],
    '.svg':  ['image/svg+xml'],

    # Documents
    '.pdf':  ['application/pdf'],
    '.doc':  ['application/msoffice'],
    '.xls':  ['application/msoffice'],
    '.ppt':  ['application/msoffice'],
    '.docx': ['application/zip'],
    '.xlsx': ['application/zip'],
    '.pptx': ['application/zip'],
    '.odt':  ['application/zip'],
    '.ods':  ['application/zip'],
    '.odp':  ['application/zip'],
    '.rtf':  ['text/rtf', 'application/rtf'],

    # Audio
    '.mp3':  ['audio/mpeg'],
    '.flac': ['audio/flac'],
    '.ogg':  ['audio/ogg', 'video/ogg'],
    '.wav':  ['audio/wav', 'audio/x-wav'],
    '.m4a':  ['video/mp4', 'audio/mp4'],
    '.aac':  ['audio/aac'],

    # Video
    '.mp4':  ['video/mp4'],
    '.mov':  ['video/mp4', 'video/quicktime'],
    '.mkv':  ['video/webm'],
    '.webm': ['video/webm'],
    '.avi':  ['video/avi', 'video/x-msvideo'],

    # Archives
    '.zip':  ['application/zip'],
    '.gz':   ['application/gzip'],
    '.bz2':  ['application/x-bzip2'],
    '.xz':   ['application/x-xz'],
    '.7z':   ['application/x-7z-compressed'],
    '.rar':  ['application/x-rar'],
    '.tar':  ['application/x-tar'],
    '.jar':  ['application/java-archive', 'application/zip'],

    # Executables
    '.exe':  ['application/x-msdownload'],
    '.dll':  ['application/x-msdownload'],
    '.elf':  ['application/x-elf'],

    # Text / Code
    '.txt':  ['text/plain'],
    '.csv':  ['text/plain', 'text/csv'],
    '.html': ['text/html', 'text/plain'],
    '.htm':  ['text/html', 'text/plain'],
    '.xml':  ['text/xml', 'application/xml', 'text/plain'],
    '.json': ['application/json', 'text/plain'],
    '.js':   ['application/javascript', 'text/plain'],
    '.css':  ['text/css', 'text/plain'],
    '.py':   ['text/x-python', 'text/plain'],
    '.sh':   ['application/x-sh', 'text/plain'],
    '.bat':  ['application/x-bat', 'text/plain'],

    # Fonts
    '.ttf':  ['font/ttf'],
    '.otf':  ['font/otf'],
    '.woff': ['font/woff'],
    '.woff2':['font/woff2'],

    # Database
    '.sqlite': ['application/x-sqlite3'],
    '.db':     ['application/x-sqlite3'],

    # Misc
    '.ps':   ['application/postscript'],
    '.swf':  ['application/x-shockwave-flash'],
}

# Risk levels for detected real types (regardless of extension)
HIGH_RISK_TYPES = {
    'application/x-msdownload',
    'application/x-elf',
    'application/x-mach-binary',
    'application/x-sh',
    'application/x-bat',
}

MEDIUM_RISK_TYPES = {
    'application/java-archive',
    'application/x-7z-compressed',
    'application/x-rar',
    'application/zip',
    'application/gzip',
    'application/x-bzip2',
    'application/x-xz',
    'application/x-tar',
    'application/x-sqlite3',
}


def _read_header(file_path: str, size: int = 512) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read(size)


def _compute_hashes(file_path: str) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return {'md5': md5.hexdigest(), 'sha256': sha256.hexdigest()}


def _compute_entropy(file_path: str) -> float:
    """Shannon entropy of the file (0–8). High entropy may indicate encryption/compression."""
    counts = [0] * 256
    total = 0
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            for byte in chunk:
                counts[byte] += 1
            total += len(chunk)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _is_text(header: bytes) -> bool:
    """Heuristic: if >85 % of the header bytes are printable ASCII, treat as text."""
    if not header:
        return False
    printable = sum(1 for b in header if 0x09 <= b <= 0x0d or 0x20 <= b <= 0x7e)
    return (printable / len(header)) > 0.85


def _detect_text_subtype(header: bytes) -> tuple:
    """Try to identify common text-based formats."""
    try:
        text = header.decode('utf-8', errors='replace').lstrip('\ufeff').lstrip()
    except Exception:
        return 'text/plain', 'Plain Text'

    stripped = text.strip()
    if stripped.startswith('<?xml') or stripped.startswith('<？xml'):
        return 'text/xml', 'XML Document'
    if stripped.startswith('<!DOCTYPE html') or stripped.lower().startswith('<html'):
        return 'text/html', 'HTML Document'
    if stripped.startswith('{') or stripped.startswith('['):
        return 'application/json', 'JSON Data'
    if stripped.startswith('#!/') or stripped.startswith('#!'):
        first_line = stripped.split('\n')[0]
        if 'python' in first_line:
            return 'text/x-python', 'Python Script'
        if 'bash' in first_line or 'sh' in first_line:
            return 'application/x-sh', 'Shell Script'
    if 'import ' in text or 'def ' in text or 'class ' in text:
        return 'text/x-python', 'Python Script'
    if stripped.startswith('body') or stripped.startswith('.') or '{' in stripped and ':' in stripped:
        return 'text/css', 'CSS Stylesheet'
    if stripped.startswith('function') or 'var ' in stripped or 'const ' in stripped or 'let ' in stripped:
        return 'application/javascript', 'JavaScript'
    # CSV heuristic: first line has commas
    first_line = stripped.split('\n')[0]
    if first_line.count(',') >= 2:
        return 'text/csv', 'CSV Data'
    return 'text/plain', 'Plain Text'


def _refine_zip(file_path: str) -> tuple:
    """Look inside ZIP to distinguish DOCX/XLSX/PPTX/ODF/JAR from plain ZIP."""
    try:
        import zipfile
        with zipfile.ZipFile(file_path, 'r') as z:
            names = z.namelist()
        if 'word/document.xml' in names:
            return 'application/zip', 'DOCX (Word Document)'
        if 'xl/workbook.xml' in names:
            return 'application/zip', 'XLSX (Excel Spreadsheet)'
        if 'ppt/presentation.xml' in names:
            return 'application/zip', 'PPTX (PowerPoint Presentation)'
        if any(n.startswith('META-INF/') for n in names):
            if any(n.endswith('.class') for n in names):
                return 'application/java-archive', 'JAR (Java Archive)'
            return 'application/zip', 'ODF / JAR Package'
        if 'mimetype' in names:
            return 'application/zip', 'ODF Document'
        return 'application/zip', 'ZIP Archive'
    except Exception:
        return 'application/zip', 'ZIP Archive'


def _refine_riff(header: bytes) -> tuple:
    """Distinguish WAV from AVI and WebP inside RIFF."""
    if len(header) >= 12:
        tag = header[8:12]
        if tag == b'WAVE':
            return 'audio/wav', 'WAV Audio'
        if tag == b'AVI ':
            return 'video/avi', 'AVI Video'
        if tag == b'WEBP':
            return 'image/webp', 'WebP Image'
    return 'application/octet-stream', 'RIFF Container'


def detect_format(file_path: str) -> dict:
    """
    Detect the actual format of a file.
    Returns: {mime_type, label, method}
    """
    header = _read_header(file_path, 512)
    if not header:
        return {'mime_type': 'application/octet-stream', 'label': 'Empty File', 'method': 'empty'}

    # Walk the signature table
    for offset, pattern, mime, label in SIGNATURES:
        end = offset + len(pattern)
        if len(header) >= end and header[offset:end] == pattern:
            if mime is None and pattern == b'RIFF':
                mime, label = _refine_riff(header)
            elif mime == 'application/zip':
                mime, label = _refine_zip(file_path)
            return {'mime_type': mime, 'label': label, 'method': 'magic_bytes'}

    # Fall back to text heuristic
    if _is_text(header):
        mime, label = _detect_text_subtype(header)
        return {'mime_type': mime, 'label': label, 'method': 'text_heuristic'}

    return {'mime_type': 'application/octet-stream', 'label': 'Unknown Binary', 'method': 'unknown'}


def assess_risk(detected_mime: str, extension: str, mismatch: bool) -> dict:
    """
    Determine risk level and reasoning.
    Returns: {level, score (0-100), reasons[]}
    """
    reasons = []
    score = 0

    if mismatch:
        score += 50
        reasons.append('File extension does not match detected format')

    if detected_mime in HIGH_RISK_TYPES:
        score += 40
        reasons.append(f'Detected format ({detected_mime}) is an executable or script')
    elif detected_mime in MEDIUM_RISK_TYPES:
        score += 20
        reasons.append(f'Detected format ({detected_mime}) is an archive or database')

    # Dangerous disguise patterns
    dangerous_disguises = {
        ('application/x-msdownload', '.pdf'),
        ('application/x-msdownload', '.jpg'),
        ('application/x-msdownload', '.docx'),
        ('application/x-msdownload', '.txt'),
        ('application/x-elf', '.pdf'),
        ('application/x-elf', '.txt'),
        ('application/x-mach-binary', '.pdf'),
        ('application/x-sh', '.txt'),
        ('application/x-sh', '.jpg'),
    }
    if (detected_mime, extension.lower()) in dangerous_disguises:
        score += 10
        reasons.append('High-risk format disguised as a benign file type')

    score = min(score, 100)

    if score >= 60:
        level = 'HIGH'
    elif score >= 30:
        level = 'MEDIUM'
    elif score >= 10:
        level = 'LOW'
    else:
        level = 'SAFE'

    if not reasons:
        reasons.append('No anomalies detected')

    return {'level': level, 'score': score, 'reasons': reasons}


def analyze_file(file_path: str, original_filename: str) -> dict:
    """
    Full analysis of a single uploaded file.
    Returns a structured report dict.
    """
    filename = original_filename
    name, ext = os.path.splitext(filename)
    ext = ext.lower()
    file_size = os.path.getsize(file_path)

    # Detect actual format
    format_info = detect_format(file_path)
    detected_mime = format_info['mime_type']
    detected_label = format_info['label']
    detection_method = format_info['method']

    # Check extension match
    expected_mimes = EXTENSION_MAP.get(ext, [])
    if not ext:
        mismatch = False
        mismatch_detail = 'No extension present'
    elif not expected_mimes:
        mismatch = False
        mismatch_detail = f'Extension "{ext}" is not in the known-extensions list'
    else:
        mismatch = detected_mime not in expected_mimes
        if mismatch:
            mismatch_detail = (
                f'Extension "{ext}" is expected to be {expected_mimes}, '
                f'but actual format is "{detected_mime}"'
            )
        else:
            mismatch_detail = 'Extension matches detected format'

    # Risk
    risk = assess_risk(detected_mime, ext, mismatch)

    # Hashes + entropy
    hashes = _compute_hashes(file_path)
    entropy = _compute_entropy(file_path)

    # Entropy note
    if entropy > 7.2:
        entropy_note = 'Very high — file may be encrypted or compressed'
    elif entropy > 6.0:
        entropy_note = 'High — file may be compressed or contain encrypted sections'
    elif entropy > 4.0:
        entropy_note = 'Moderate — typical for mixed binary/text content'
    else:
        entropy_note = 'Low — typical for text or structured data'

    return {
        'filename': filename,
        'extension': ext if ext else '(none)',
        'file_size': file_size,
        'file_size_human': _human_size(file_size),
        'detected_mime': detected_mime,
        'detected_label': detected_label,
        'detection_method': detection_method,
        'expected_mimes': expected_mimes,
        'mismatch': mismatch,
        'mismatch_detail': mismatch_detail,
        'risk': risk,
        'hashes': hashes,
        'entropy': entropy,
        'entropy_note': entropy_note,
        'analyzed_at': datetime.utcnow().isoformat() + 'Z',
    }


def _human_size(size: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'
