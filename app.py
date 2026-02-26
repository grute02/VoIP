"""
SIM Box 탐지 시스템 - Flask 백엔드
Team C (현서)

API 목록:
  GET  /api/sessions            세션 목록 조회
  GET  /api/sessions/<id>       세션 상세 조회
  GET  /api/stats               통계 요약
  POST /api/analyze             분석 결과 수신 (광준님 모델 → 여기로 POST)
  POST /api/upload-pcap         PCAP 파일 업로드 → 자동 파싱 → DB 저장
"""

import os
import sqlite3
import tempfile
from datetime import datetime

from flask import Flask, jsonify, request, g

# rtp_parser는 src/parser/ 안에 있으므로 경로 등록
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "parser"))
from rtp_parser import process_pcap

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────

app    = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")

ALLOWED_EXTENSIONS = {"pcap", "pcapng"}
MAX_UPLOAD_MB      = 50


# ──────────────────────────────────────────────
# DB 헬퍼
# ──────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def _row_to_dict(row) -> dict:
    return dict(row)


# ──────────────────────────────────────────────
# 유틸
# ──────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ──────────────────────────────────────────────
# API: 세션 목록
# ──────────────────────────────────────────────

@app.route("/api/sessions", methods=["GET"])
def get_sessions():
    """
    GET /api/sessions?label=0|1&limit=50&offset=0
    """
    label  = request.args.get("label",  type=int)
    limit  = request.args.get("limit",  default=50,  type=int)
    offset = request.args.get("offset", default=0,   type=int)

    db    = get_db()
    query = "SELECT * FROM call_session"
    params = []

    if label is not None:
        query += " WHERE label = ?"
        params.append(label)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    rows = db.execute(query, params).fetchall()
    return jsonify([_row_to_dict(r) for r in rows])


# ──────────────────────────────────────────────
# API: 세션 상세
# ──────────────────────────────────────────────

@app.route("/api/sessions/<session_id>", methods=["GET"])
def get_session(session_id: str):
    db  = get_db()
    row = db.execute(
        "SELECT * FROM call_session WHERE session_id = ?", (session_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "세션 없음"}), 404

    session = _row_to_dict(row)

    # 탐지 결과도 함께 반환
    results = db.execute(
        "SELECT * FROM detection_result WHERE session_id = ? ORDER BY detected_at DESC",
        (session_id,),
    ).fetchall()
    session["detection_results"] = [_row_to_dict(r) for r in results]

    return jsonify(session)


# ──────────────────────────────────────────────
# API: 통계 요약
# ──────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def get_stats():
    db = get_db()

    total    = db.execute("SELECT COUNT(*) FROM call_session").fetchone()[0]
    normal   = db.execute("SELECT COUNT(*) FROM call_session WHERE label=0").fetchone()[0]
    fraud    = db.execute("SELECT COUNT(*) FROM call_session WHERE label=1").fetchone()[0]
    unlabel  = db.execute("SELECT COUNT(*) FROM call_session WHERE label=-1").fetchone()[0]

    avg_row  = db.execute(
        "SELECT AVG(avg_latency), AVG(avg_jitter), AVG(packet_loss) FROM call_session"
    ).fetchone()

    return jsonify({
        "total"          : total,
        "normal"         : normal,
        "fraud"          : fraud,
        "unlabeled"      : unlabel,
        "avg_latency_ms" : round(avg_row[0] or 0, 2),
        "avg_jitter_ms"  : round(avg_row[1] or 0, 2),
        "avg_packet_loss": round(avg_row[2] or 0, 4),
        "updated_at"     : datetime.now().isoformat(),
    })


# ──────────────────────────────────────────────
# API: 분석 결과 수신 (광준님 모델 → POST)
# ──────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def receive_analysis():
    """
    광준님 ML 스크립트가 예측 결과를 여기로 POST합니다.

    요청 Body (JSON):
    {
      "session_id": "fraud_0001",
      "model_name": "random_forest",
      "risk_score": 0.87,
      "result"    : "suspicious"
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON Body 필요"}), 400

    required = ["session_id", "model_name", "risk_score", "result"]
    missing  = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": f"필드 누락: {missing}"}), 400

    db = get_db()

    # 세션 존재 여부 확인
    row = db.execute(
        "SELECT 1 FROM call_session WHERE session_id=?", (data["session_id"],)
    ).fetchone()
    if row is None:
        return jsonify({"error": f"session_id 없음: {data['session_id']}"}), 404

    db.execute(
        """
        INSERT INTO detection_result (session_id, model_name, risk_score, result)
        VALUES (?, ?, ?, ?)
        """,
        (data["session_id"], data["model_name"],
         float(data["risk_score"]), data["result"]),
    )
    db.commit()

    return jsonify({"status": "ok", "session_id": data["session_id"]}), 201


# ──────────────────────────────────────────────
# API: PCAP 업로드 → 자동 파싱 → DB 저장
# ──────────────────────────────────────────────

@app.route("/api/upload-pcap", methods=["POST"])
def upload_pcap():
    """
    PCAP 파일을 업로드하면 rtp_parser가 자동 파싱 후 DB에 저장합니다.

    Form-data:
      file  : PCAP 파일
      label : 0 (정상) | 1 (사기) | -1 (미라벨, 기본값)

    curl 예시:
      curl -X POST http://127.0.0.1:5000/api/upload-pcap \\
           -F "file=@data/raw/fraud.pcap" \\
           -F "label=1"
    """
    if "file" not in request.files:
        return jsonify({"error": "file 필드 없음"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "파일명 없음"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "pcap / pcapng 만 허용됩니다"}), 415

    label = request.form.get("label", default=-1, type=int)

    # 임시 파일로 저장 후 파서 실행
    suffix = "." + file.filename.rsplit(".", 1)[1].lower()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = tmp.name
        file.save(tmp_path)

    try:
        sessions = process_pcap(tmp_path, label=label)
    except Exception as e:
        os.unlink(tmp_path)
        return jsonify({"error": f"파서 오류: {str(e)}"}), 500
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    if not sessions:
        return jsonify({
            "status" : "warn",
            "message": "파싱된 세션 없음 — RTP 포트(10000-20000) 패킷 확인 필요",
            "inserted": 0,
        }), 200

    # DB 저장
    db       = get_db()
    inserted = 0
    skipped  = 0

    for s in sessions:
        try:
            db.execute(
                """
                INSERT OR IGNORE INTO call_session
                  (session_id, avg_latency, avg_jitter, iat_variance,
                   packet_loss, seq_gap_rate, label)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    s["session_id"],
                    s["avg_latency"],
                    s["avg_jitter"],
                    s.get("iat_variance", 0.0),
                    s["packet_loss"],
                    s["seq_gap_rate"],
                    s["label"],
                ),
            )
            if db.execute("SELECT changes()").fetchone()[0]:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"[WARN] DB 삽입 실패 ({s['session_id']}): {e}")

    db.commit()

    return jsonify({
        "status"  : "ok",
        "inserted": inserted,
        "skipped" : skipped,
        "sessions": sessions,
    }), 201


# ──────────────────────────────────────────────
# 대시보드 루트
# ──────────────────────────────────────────────

@app.route("/")
def index():
    from flask import render_template
    return render_template("index.html")


# ──────────────────────────────────────────────
# 실행
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # DB 없으면 자동 초기화
    if not os.path.exists(DB_PATH):
        from init_db import init_db
        init_db()

    app.run(host="127.0.0.1", port=5000, debug=True)
