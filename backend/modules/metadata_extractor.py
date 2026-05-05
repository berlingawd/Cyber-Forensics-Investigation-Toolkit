"""
Metadata Extractor Module
=========================
Extracts hidden metadata from common file types used in forensic investigations.

Supported file types:
  - Images  (.jpg .jpeg .png .tiff .bmp .webp .gif)  → Camera make/model, GPS, timestamp
  - PDFs    (.pdf)                                    → Author, title, creator, dates
  - Office  (.docx .xlsx .pptx)                       → Author, company, revision, dates
  - Any     (fallback)                                → File size, timestamps

No required external libraries — Pillow and pypdf are optional enhancements.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    try:
        from PyPDF2 import PdfReader
        PYPDF_AVAILABLE = True
    except ImportError:
        PYPDF_AVAILABLE = False

IMAGE_EXTENSIONS  = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp", ".gif"}
PDF_EXTENSIONS    = {".pdf"}
OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}


def _format_ts(unix_ts: float) -> str:
    return datetime.fromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S")


def _gps_to_decimal(dms_tuple, ref: str):
    try:
        d = float(dms_tuple[0])
        m = float(dms_tuple[1])
        s = float(dms_tuple[2])
        decimal = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return None


def _extract_basic_metadata(path: Path) -> dict:
    stat = path.stat()
    size_bytes = stat.st_size
    size_kb = size_bytes / 1024
    size_mb = size_kb / 1024

    if size_mb >= 1:
        human_size = f"{size_mb:.2f} MB  ({size_bytes:,} bytes)"
    elif size_kb >= 1:
        human_size = f"{size_kb:.1f} KB  ({size_bytes:,} bytes)"
    else:
        human_size = f"{size_bytes} bytes"

    return {
        "file_name":   path.name,
        "file_size":   human_size,
        "extension":   path.suffix.lower() or "(none)",
        "created_at":  _format_ts(stat.st_ctime),
        "modified_at": _format_ts(stat.st_mtime),
        "accessed_at": _format_ts(stat.st_atime),
    }


def _extract_image_metadata(path: Path) -> dict:
    if not PILLOW_AVAILABLE:
        return {"note": "Pillow not installed. Run: pip install Pillow"}

    result = {}
    try:
        img = Image.open(str(path))
        result["image_format"] = img.format or "Unknown"
        result["image_mode"]   = img.mode
        result["dimensions"]   = f"{img.width} x {img.height} pixels"

        raw_exif = getattr(img, "_getexif", lambda: None)()
        if raw_exif is None:
            result["exif_note"] = "No EXIF data embedded in this image."
            return result

        gps_raw = {}
        readable = {}

        for tag_id, value in raw_exif.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            if tag_name == "GPSInfo":
                for gps_id, gps_val in value.items():
                    gps_name = GPSTAGS.get(gps_id, str(gps_id))
                    gps_raw[gps_name] = gps_val
            elif isinstance(value, (str, int, float)):
                readable[tag_name] = str(value)

        if gps_raw:
            lat = _gps_to_decimal(gps_raw.get("GPSLatitude", ()), gps_raw.get("GPSLatitudeRef", "N"))
            lon = _gps_to_decimal(gps_raw.get("GPSLongitude", ()), gps_raw.get("GPSLongitudeRef", "E"))
            gps_info = {}
            if lat is not None and lon is not None:
                gps_info["latitude"]    = lat
                gps_info["longitude"]   = lon
                gps_info["google_maps"] = f"https://www.google.com/maps?q={lat},{lon}"
            alt = gps_raw.get("GPSAltitude")
            if alt is not None:
                try:
                    gps_info["altitude_m"] = round(float(alt), 1)
                except Exception:
                    pass
            result["gps_location"] = gps_info if gps_info else "GPS tags present but coordinates incomplete."

        FORENSIC_FIELDS = (
            "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
            "DateTimeDigitized", "Artist", "Copyright", "ImageDescription",
        )
        result["key_metadata"] = {k: readable[k] for k in FORENSIC_FIELDS if k in readable}
        result["all_exif_fields"] = readable

    except Exception as exc:
        result["error"] = f"Could not read image EXIF: {exc}"

    return result


def _extract_pdf_raw_fallback(path: Path) -> dict:
    result = {"note": "pypdf not installed. Run: pip install pypdf\nShowing partial metadata:"}
    try:
        text = path.read_bytes().decode("latin-1", errors="replace")
        fields = ("Author", "Title", "Subject", "Creator", "Producer", "CreationDate", "ModDate", "Keywords")
        for field in fields:
            m = re.search(rf"/{field}\s*\(([^)]+)\)", text)
            if m:
                result[field] = m.group(1).strip()
    except Exception as exc:
        result["raw_parse_error"] = str(exc)
    return result


def _extract_pdf_metadata(path: Path) -> dict:
    if not PYPDF_AVAILABLE:
        return _extract_pdf_raw_fallback(path)

    result = {}
    try:
        reader = PdfReader(str(path))
        info = reader.metadata
        FIELD_MAP = {
            "/Author":       "Author",
            "/Title":        "Title",
            "/Subject":      "Subject",
            "/Creator":      "Creator (app that created the document)",
            "/Producer":     "Producer (app that made the PDF)",
            "/CreationDate": "Created At",
            "/ModDate":      "Modified At",
            "/Keywords":     "Keywords",
            "/Company":      "Company",
        }
        if info:
            for pdf_key, label in FIELD_MAP.items():
                val = info.get(pdf_key)
                if val:
                    result[label] = str(val)

        result["total_pages"] = len(reader.pages)
        result["encrypted"]   = reader.is_encrypted
    except Exception as exc:
        result["error"] = f"Could not parse PDF: {exc}"

    return result


def _extract_office_metadata(path: Path) -> dict:
    result = {}
    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            names = zf.namelist()

            if "docProps/core.xml" in names:
                xml_bytes = zf.read("docProps/core.xml")
                root = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))
                NS = {
                    "dc":      "http://purl.org/dc/elements/1.1/",
                    "cp":      "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    "dcterms": "http://purl.org/dc/terms/",
                }

                def find(tag, ns_key):
                    el = root.find(f"{{{NS[ns_key]}}}{tag}")
                    return el.text.strip() if el is not None and el.text else None

                v = find("creator", "dc");        result["Author"]           = v if v else result.get("Author")
                v = find("lastModifiedBy", "cp"); result["Last Modified By"] = v if v else result.get("Last Modified By")
                v = find("created", "dcterms");   result["Created At"]       = v if v else result.get("Created At")
                v = find("modified", "dcterms");  result["Modified At"]      = v if v else result.get("Modified At")
                v = find("revision", "cp");       result["Revision Number"]  = v if v else result.get("Revision Number")
                v = find("keywords", "cp");       result["Keywords"]         = v if v else result.get("Keywords")
                # Clean out None values
                result = {k: v for k, v in result.items() if v}

            if "docProps/app.xml" in names:
                xml_bytes = zf.read("docProps/app.xml")
                root2 = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))
                APP_NS = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"

                def find_app(tag):
                    el = root2.find(f"{{{APP_NS}}}{tag}")
                    return el.text.strip() if el is not None and el.text else None

                for tag, label in [("Application","Application"),("Company","Company"),
                                   ("AppVersion","App Version"),("Pages","Page Count"),
                                   ("Words","Word Count"),("Slides","Slide Count")]:
                    v = find_app(tag)
                    if v:
                        result[label] = v

        if not result:
            result["note"] = "No metadata found in Office document properties."

    except zipfile.BadZipFile:
        result["error"] = "File is not a valid Office document."
    except Exception as exc:
        result["error"] = f"Could not read Office metadata: {exc}"

    return result


def extract_metadata(file_path: str) -> dict:
    """
    Detect file type and extract the most forensically useful metadata.

    Returns:
        {file_info, type_metadata, file_type_label, error}
    """
    path = Path(file_path)

    if not path.exists():
        return {
            "file_info":       {},
            "type_metadata":   {},
            "file_type_label": "Unknown",
            "error":           f"File not found: {file_path}",
        }

    ext = path.suffix.lower()
    file_info = _extract_basic_metadata(path)

    if ext in IMAGE_EXTENSIONS:
        label     = "Image File (EXIF)"
        type_meta = _extract_image_metadata(path)
    elif ext in PDF_EXTENSIONS:
        label     = "PDF Document"
        type_meta = _extract_pdf_metadata(path)
    elif ext in OFFICE_EXTENSIONS:
        label     = "Office Document (Open XML)"
        type_meta = _extract_office_metadata(path)
    else:
        label     = "Generic File"
        type_meta = {
            "note": (
                f"No specialized extractor for '{ext}' files.\n"
                "File system information is shown above.\n"
                "Supported: images (jpg/png/tiff), PDF, Office (docx/xlsx/pptx)."
            )
        }

    return {
        "file_info":       file_info,
        "type_metadata":   type_meta,
        "file_type_label": label,
        "error":           None,
    }
