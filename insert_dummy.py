"""
더미 데이터 DB 삽입 스크립트
generate_dummy.py 실행 후 사용: python insert_dummy.py

사용 순서:
  1. python init_db.py
  2. python src/parser/generate_dummy.py
  3. python insert_dummy.py
"""

import sqlite3
import pandas as pd
import os

DB_PATH  = "database.db"
CSV_PATH = "data/processed/sessions_dummy.csv"


def insert_dummy():
    if not os.path.exists(CSV_PATH):
        print(f"[ERROR] CSV 없음: {CSV_PATH}")
        print("  → 먼저 python src/parser/generate_dummy.py 를 실행하세요.")
        return

    df = pd.read_csv(CSV_PATH, encoding="utf-8")
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    inserted = 0
    skipped  = 0

    for _, row in df.iterrows():
        try:
            cur.execute(
                """
                INSERT OR IGNORE INTO call_session
                  (session_id, avg_latency, avg_jitter, iat_variance,
                   packet_loss, seq_gap_rate, label)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["session_id"],
                    row["avg_latency"],
                    row["avg_jitter"],
                    row.get("iat_variance", 0.0),
                    row["packet_loss"],
                    row["seq_gap_rate"],
                    int(row["label"]),
                ),
            )
            if cur.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"[WARN] 삽입 실패 ({row['session_id']}): {e}")

    conn.commit()
    conn.close()
    print(f"[OK] 삽입 완료 — 신규: {inserted}개 / 중복 스킵: {skipped}개")


if __name__ == "__main__":
    insert_dummy()
