"""
더미 데이터 생성기 - Team C (현서)
실제 PCAP 없이도 ML 개발을 병행할 수 있도록
rtp_parser.py와 동일한 컬럼 구조의 CSV를 생성합니다.

출력 컬럼: session_id, avg_latency, avg_jitter, iat_variance,
           packet_loss, seq_gap_rate, label
"""

import os
import random
import pandas as pd

random.seed(42)


def generate_normal_session(idx: int) -> dict:
    """정상 통화 세션 (낮은 지연/지터)"""
    return {
        "session_id"  : f"normal_{idx:04d}",
        "avg_latency" : round(random.uniform(20, 50), 4),     # 20~50 ms
        "avg_jitter"  : round(random.uniform(1, 5),   4),     # 1~5 ms
        "iat_variance": round(random.uniform(0.1, 1), 4),
        "packet_loss" : round(random.uniform(0, 0.02), 4),    # 0~2%
        "seq_gap_rate": round(random.uniform(0, 0.01), 4),
        "label"       : 0,
    }


def generate_fraud_session(idx: int) -> dict:
    """SIM Box 사기 통화 세션 (높은 지연/지터)"""
    return {
        "session_id"  : f"fraud_{idx:04d}",
        "avg_latency" : round(random.uniform(100, 300), 4),   # 100~300 ms
        "avg_jitter"  : round(random.uniform(20, 80),   4),   # 20~80 ms
        "iat_variance": round(random.uniform(5, 30),    4),
        "packet_loss" : round(random.uniform(0.05, 0.20), 4), # 5~20%
        "seq_gap_rate": round(random.uniform(0.05, 0.30), 4),
        "label"       : 1,
    }


def generate_dummy_csv(
    normal_count: int = 50,
    fraud_count : int = 50,
    output_path : str = "data/processed/sessions_dummy.csv",
) -> pd.DataFrame:

    rows  = [generate_normal_session(i) for i in range(normal_count)]
    rows += [generate_fraud_session(i)  for i in range(fraud_count)]

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False, encoding="utf-8")

    print(f"[OK] 더미 데이터 생성 완료: {output_path}")
    print(f"     정상 {normal_count}개 / 사기 {fraud_count}개 / 합계 {len(df)}개")
    return df


if __name__ == "__main__":
    df = generate_dummy_csv()
    print(df.head())
