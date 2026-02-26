-- SIM Box 탐지 시스템 DB 스키마
-- call_session: 파서가 추출한 세션 단위 특징
-- detection_result: 모델 예측 결과

PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS call_session (
    session_id   TEXT PRIMARY KEY,
    avg_latency  REAL NOT NULL,   -- 평균 IAT (ms)
    avg_jitter   REAL NOT NULL,   -- RFC 3550 평균 지터 (ms)
    iat_variance REAL NOT NULL,   -- IAT 분산 (ms²)
    packet_loss  REAL NOT NULL,   -- 패킷 손실률 (0~1)
    seq_gap_rate REAL NOT NULL,   -- 시퀀스 갭 비율 (0~1)
    label        INTEGER DEFAULT -1,  -- 0=정상 1=사기 -1=미라벨
    created_at   TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS detection_result (
    result_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES call_session(session_id),
    model_name  TEXT NOT NULL,   -- 'random_forest' | 'isolation_forest'
    risk_score  REAL NOT NULL,   -- 0.0 ~ 1.0
    result      TEXT NOT NULL,   -- 'normal' | 'suspicious'
    detected_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_result_session ON detection_result(session_id);
CREATE INDEX IF NOT EXISTS idx_session_label  ON call_session(label);
