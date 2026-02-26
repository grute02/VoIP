"""
DB 초기화 스크립트
처음 한 번만 실행하면 됩니다: python init_db.py
"""

import sqlite3
import os

DB_PATH     = "database.db"
SCHEMA_PATH = "schema.sql"


def init_db():
    if os.path.exists(DB_PATH):
        print(f"[INFO] 기존 DB 발견: {DB_PATH} — 스키마 재적용")
    else:
        print(f"[INFO] DB 새로 생성: {DB_PATH}")

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(schema)

    # ── 마이그레이션: 새 컬럼 누락 시 자동 추가 ──
    # 스키마를 바꿔도 기존 DB에 컬럼이 없으면 INSERT가 실패하므로
    # ALTER TABLE로 빠진 컬럼을 채워준다.
    REQUIRED_COLUMNS = {
        "call_session": [
            ("iat_variance", "REAL NOT NULL DEFAULT 0.0"),
        ]
    }

    cur = conn.cursor()
    for table, columns in REQUIRED_COLUMNS.items():
        existing = {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
        for col_name, col_def in columns:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                print(f"[MIGRATE] {table}.{col_name} 컬럼 추가")

    conn.commit()
    conn.close()
    print("[OK] DB 초기화 완료")


if __name__ == "__main__":
    init_db()
