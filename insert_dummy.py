import sqlite3
import random
from datetime import datetime

def insert_dummy_data():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # 가짜 데이터 생성 (마치 Scapy가 분석한 것처럼!)
    session_id = f"TEST_SESSION_{random.randint(1000, 9999)}"
    avg_latency = 150.5  # 150ms 지연
    avg_jitter = 45.2    # 45ms 지터 (상당히 높음)
    packet_loss = 2.5    # 2.5% 손실
    
    print(f"🛠️ 가짜 데이터 생성 중... ID: {session_id}")

    try:
        cursor.execute('''
            INSERT INTO call_session (session_id, avg_latency, avg_jitter, packet_loss, seq_gap_rate, label)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, avg_latency, avg_jitter, packet_loss, 0.1, 1)) # label 1 = 사기 의심
        
        conn.commit()
        print("✅ 데이터가 성공적으로 DB에 들어갔어!")
    except Exception as e:
        print(f"❌ 에러 발생: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    insert_dummy_data()