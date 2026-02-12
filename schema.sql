-- 1. 통화 세션 정보 테이블 (CallSession)
CREATE TABLE IF NOT EXISTS call_session (
    session_id TEXT PRIMARY KEY,
    avg_latency REAL,
    avg_jitter REAL,
    packet_loss REAL,
    seq_gap_rate REAL,
    label INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. 탐지 결과 테이블 (DetectionResult)
CREATE TABLE IF NOT EXISTS detection_result (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    model_name TEXT,
    risk_score REAL,
    result TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES call_session (session_id)
);