"""
Cyber Forensics Investigation Toolkit
======================================
Run:  python main.py
Open: http://127.0.0.1:5000/
"""

from __future__ import annotations

import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from backend.modules import evidence_storage
from backend.modules.hash_checker import verify_evidence_integrity
from backend.modules.log_analyzer import parse_auth_log
from backend.modules.malware_scanner import scan_file
from backend.modules.metadata_extractor import extract_metadata
from backend.modules.pcap_analyzer import analyze_pcap
from backend.modules.phishing_detector import analyze_email
from backend.modules.report_generator import generate_forensic_report
from backend.modules.timeline_generator import generate_timeline_from_log_file

ROOT         = Path(__file__).resolve().parent
EVIDENCE_DIR = ROOT / "evidence"
REPORTS_DIR  = ROOT / "reports"
YARA_RULES   = ROOT / "sample_data" / "sample_rules.yar"

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(ROOT / "frontend" / "templates"),
    static_folder=str(ROOT / "static"),
    static_url_path="/static",
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ensure_default_case() -> None:
    if evidence_storage.get_case("default-case") is None:
        evidence_storage.create_case("default-case", "Default Case", "Investigator")


def _safe_evidence_path(file_name: str | None) -> Path | None:
    """Return the absolute path only if the file exists inside EVIDENCE_DIR."""
    if not file_name or not isinstance(file_name, str):
        return None
    base = secure_filename(Path(file_name.strip()).name)
    if not base:
        return None
    path = (EVIDENCE_DIR / base).resolve()
    try:
        path.relative_to(EVIDENCE_DIR.resolve())
    except ValueError:
        return None
    return path if path.is_file() else None


def _evidence_summary_for_pdf(rows: list) -> list:
    return [
        {
            "file_name":          e.get("file_name", ""),
            "hash_sha256":        e.get("hash_sha256"),
            "timestamp_collected": e.get("timestamp_collected", ""),
            "evidence_status":    "VERIFIED - Integrity preserved" if e.get("hash_sha256") else "Recorded",
        }
        for e in rows
    ]


def _log_analysis_for_case(evidence_rows: list) -> tuple:
    for e in evidence_rows:
        fn = e.get("file_name") or ""
        et = (e.get("evidence_type") or "").lower()
        if et == "log" or fn.lower().endswith(".log"):
            p = _safe_evidence_path(fn)
            if p:
                r = parse_auth_log(str(p))
                if r.get("error"):
                    continue
                attacks = r.get("suspicious_ips") or []
                ips = [x.get("suspicious_ip") for x in attacks if x.get("suspicious_ip")]
                return attacks, ips
    return [], []


# ── Page Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload")
def upload_page():
    _ensure_default_case()
    cases = evidence_storage.get_all_cases()
    return render_template("upload.html", cases=cases)


@app.route("/dashboard")
def dashboard():
    _ensure_default_case()
    cases    = evidence_storage.get_all_cases()
    case_id  = request.args.get("case_id")
    current_case = None
    if case_id:
        current_case = evidence_storage.get_case(case_id)
    if not current_case and cases:
        current_case = evidence_storage.get_case(cases[0]["case_id"])
    evidence_list = (
        evidence_storage.get_evidence_by_case(current_case["case_id"]) if current_case else []
    )
    timeline = (
        evidence_storage.get_timeline_events(current_case["case_id"]) if current_case else []
    )
    return render_template(
        "dashboard.html",
        cases=cases,
        current_case=current_case,
        evidence_list=evidence_list,
        timeline=timeline,
    )


# ── API Routes ────────────────────────────────────────────────────────────────

@app.post("/api/upload")
def api_upload():
    _ensure_default_case()
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file"}), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"success": False, "error": "Empty filename"}), 400

    original    = secure_filename(f.filename)
    stored_name = f"{uuid.uuid4().hex[:12]}_{original}"
    dest        = EVIDENCE_DIR / stored_name
    f.save(str(dest))

    integrity        = verify_evidence_integrity(str(dest))
    case_id          = request.form.get("case_id") or "default-case"
    investigator     = request.form.get("investigator_name") or ""
    evidence_type    = request.form.get("evidence_type") or "file"

    evidence_storage.add_evidence(
        case_id=case_id,
        file_name=stored_name,
        file_path=str(dest),
        hash_md5=integrity.get("md5"),
        hash_sha1=integrity.get("sha1"),
        hash_sha256=integrity.get("sha256"),
        investigator_name=investigator,
        evidence_type=evidence_type,
    )

    return jsonify({
        "success": True,
        "original_name": original,
        "stored_name":   stored_name,
        "integrity":     integrity,
    })


@app.post("/api/verify_hash")
def api_verify_hash():
    data = request.get_json(silent=True) or {}
    path = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found"}), 404
    return jsonify({"success": True, "integrity": verify_evidence_integrity(str(path))})


@app.post("/api/analyze_log")
def api_analyze_log():
    data = request.get_json(silent=True) or {}
    path = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found in evidence vault"}), 404
    return jsonify({"success": True, "result": parse_auth_log(str(path))})


@app.post("/api/analyze_pcap")
def api_analyze_pcap():
    data = request.get_json(silent=True) or {}
    path = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found in evidence vault"}), 404
    return jsonify({"success": True, "result": analyze_pcap(str(path))})


@app.post("/api/timeline")
def api_timeline():
    data    = request.get_json(silent=True) or {}
    case_id = data.get("case_id")
    path    = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found in evidence vault"}), 404
    tl = generate_timeline_from_log_file(str(path))
    if case_id:
        for ev in tl:
            evidence_storage.add_timeline_event(case_id, ev.get("time_str", ""), ev.get("event", ""), "log")
    return jsonify({"success": True, "timeline": tl})


@app.post("/api/scan_malware")
def api_scan_malware():
    data = request.get_json(silent=True) or {}
    path = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found in evidence vault"}), 404
    yara_path = str(YARA_RULES) if YARA_RULES.is_file() else None
    return jsonify({"success": True, "result": scan_file(str(path), yara_rules_path=yara_path)})


@app.post("/api/extract_metadata")
def api_extract_metadata():
    data = request.get_json(silent=True) or {}
    path = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found in evidence vault"}), 404
    return jsonify({"success": True, "result": extract_metadata(str(path))})


@app.post("/api/analyze_email")
def api_analyze_email():
    data = request.get_json(silent=True) or {}
    path = _safe_evidence_path(data.get("file_name") or data.get("file_path"))
    if not path:
        return jsonify({"success": False, "error": "File not found in evidence vault"}), 404
    return jsonify({"success": True, "result": analyze_email(str(path))})


@app.get("/api/cases")
def api_cases_list():
    _ensure_default_case()
    return jsonify({"success": True, "cases": evidence_storage.get_all_cases()})


@app.post("/api/cases")
def api_cases_create():
    data    = request.get_json(silent=True) or {}
    name    = (data.get("case_name") or "New Case").strip()
    inv     = (data.get("investigator_name") or "Investigator").strip()
    case_id = f"case-{uuid.uuid4().hex[:8]}"
    ok = evidence_storage.create_case(case_id, name, inv)
    if not ok:
        return jsonify({"success": False, "error": "Could not create case"}), 500
    return jsonify({"success": True, "case_id": case_id})


@app.get("/api/cases/<case_id>")
def api_case_detail(case_id: str):
    c = evidence_storage.get_case(case_id)
    if not c:
        return jsonify({"success": False, "error": "Case not found"}), 404
    ev = evidence_storage.get_evidence_by_case(case_id)
    tl = evidence_storage.get_timeline_events(case_id)
    return jsonify({"success": True, "case": c, "evidence": ev, "timeline": tl})


@app.post("/api/generate_report")
def api_generate_report():
    _ensure_default_case()
    data       = request.get_json(silent=True) or {}
    case_id    = data.get("case_id")
    conclusion = (data.get("conclusion") or "").strip() or "Investigation in progress."
    if not case_id:
        return jsonify({"success": False, "error": "case_id required"}), 400

    case = evidence_storage.get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    evidence_rows = evidence_storage.get_evidence_by_case(case_id)
    summary       = _evidence_summary_for_pdf(evidence_rows)
    attacks, suspicious = _log_analysis_for_case(evidence_rows)

    timeline = evidence_storage.get_timeline_events(case_id)
    if not timeline:
        for e in evidence_rows:
            fn = e.get("file_name") or ""
            if fn.lower().endswith(".log"):
                p = _safe_evidence_path(fn)
                if p:
                    timeline = generate_timeline_from_log_file(str(p))
                    break

    report_name = f"report_{case_id}_{uuid.uuid4().hex[:8]}.pdf"
    out_path    = REPORTS_DIR / report_name

    try:
        generate_forensic_report(
            output_path=str(out_path),
            case_id=case_id,
            case_name=case.get("case_name") or "",
            investigator_name=case.get("investigator_name") or "",
            evidence_summary=summary,
            detected_attacks=attacks,
            suspicious_ips=suspicious,
            timeline_events=timeline,
            conclusion=conclusion,
        )
    except Exception as exc:
        return jsonify({"success": False, "error": f"PDF generation failed: {exc}"}), 500

    return jsonify({"success": True, "report_file": report_name})


@app.get("/reports/<path:filename>")
def serve_report(filename: str):
    safe = secure_filename(filename)
    if not safe or safe != Path(filename).name:
        return jsonify({"error": "Invalid filename"}), 400
    path = REPORTS_DIR / safe
    if not path.is_file():
        return jsonify({"error": "Report not found"}), 404
    return send_from_directory(
        str(REPORTS_DIR), safe,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=safe,
        max_age=0,
    )


if __name__ == "__main__":
    _ensure_default_case()
    print("=" * 50)
    print("  Cyber Forensics Investigation Toolkit")
    print("  Open: http://127.0.0.1:5000/")
    print("=" * 50)
    app.run(debug=True, host="127.0.0.1", port=5000)
