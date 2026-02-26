"""
RTP 패킷 파서 - Team C (현서)
PCAP 파일에서 RTP 헤더를 파싱하고 세션 단위 특징을 추출합니다.

출력 컬럼 (광준님 Feature Engineering과 동일):
  session_id, avg_latency, avg_jitter, packet_loss, seq_gap_rate, label
"""

import struct
import os
import pandas as pd
from scapy.all import rdpcap, UDP

# RTP 미디어 포트 범위
RTP_PORT_MIN = 10000
RTP_PORT_MAX = 20000

# G.711 기준 클락 레이트 (Hz)
CLOCK_RATE = 8000


# ──────────────────────────────────────────────
# 1. RTP 헤더 파싱
# ──────────────────────────────────────────────

def parse_rtp_header(payload: bytes):
    """UDP payload에서 RTP 헤더를 파싱합니다."""
    if len(payload) < 12:
        return None

    version = (payload[0] >> 6) & 0x3
    if version != 2:          # RTP 버전은 반드시 2
        return None

    seq_num   = struct.unpack('!H', payload[2:4])[0]
    timestamp = struct.unpack('!I', payload[4:8])[0]
    ssrc      = struct.unpack('!I', payload[8:12])[0]

    return {"seq_num": seq_num, "timestamp": timestamp, "ssrc": ssrc}


# ──────────────────────────────────────────────
# 2. 패킷 리스트 → IAT / 지터 계산
# ──────────────────────────────────────────────

def calculate_features(rtp_packets: list, clock_rate: int = CLOCK_RATE) -> dict:
    """
    패킷 레코드 리스트를 받아 세션 단위 특징을 계산합니다.

    rtp_packets 형식:
        [{"seq_num": int, "timestamp": int, "arrival_time": float}, ...]

    반환값:
        {
          "avg_latency"  : float,  # 평균 IAT (ms)
          "avg_jitter"   : float,  # RFC 3550 평균 지터 (ms)
          "iat_variance" : float,  # IAT 분산 (광준님 Feature 추가)
          "packet_loss"  : float,  # 패킷 손실률 (0~1)
          "seq_gap_rate" : float,  # 시퀀스 갭 비율 (0~1)
        }
    """
    if len(rtp_packets) < 2:
        return None

    records = []
    jitter  = 0.0

    for i in range(1, len(rtp_packets)):
        prev = rtp_packets[i - 1]
        curr = rtp_packets[i]

        # IAT: 실제 도착 시간 차이 (초)
        iat_sec = curr["arrival_time"] - prev["arrival_time"]

        # RFC 3550 지터 계산
        # D = |transit_curr - transit_prev|
        transit_diff = abs(
            (curr["arrival_time"] - curr["timestamp"] / clock_rate)
            - (prev["arrival_time"] - prev["timestamp"] / clock_rate)
        )
        jitter += (transit_diff - jitter) / 16.0

        records.append({
            "iat_sec": iat_sec,
            "jitter":  jitter,
        })

    iats    = [r["iat_sec"]  for r in records]
    jitters = [r["jitter"]   for r in records]

    avg_latency  = float(pd.Series(iats).mean()    * 1000)   # ms
    avg_jitter   = float(pd.Series(jitters).mean() * 1000)   # ms
    iat_variance = float(pd.Series(iats).var()     * 1e6)    # ms² 스케일

    # 패킷 손실률
    seqs     = [p["seq_num"] for p in rtp_packets]
    expected = (max(seqs) - min(seqs) + 1) if len(seqs) > 1 else 1
    received = len(set(seqs))
    packet_loss  = max(0.0, (expected - received) / expected)

    # 시퀀스 갭 비율 (연속되지 않은 구간 / 전체 구간)
    gaps = sum(
        1 for j in range(1, len(seqs))
        if seqs[j] - seqs[j - 1] != 1
    )
    seq_gap_rate = gaps / max(len(seqs) - 1, 1)

    return {
        "avg_latency" : round(avg_latency,  4),
        "avg_jitter"  : round(avg_jitter,   4),
        "iat_variance": round(iat_variance, 4),
        "packet_loss" : round(packet_loss,  4),
        "seq_gap_rate": round(seq_gap_rate, 4),
    }


# ──────────────────────────────────────────────
# 3. 세션 집계
# ──────────────────────────────────────────────

def aggregate_session(rtp_records: list, session_id: str, label: int = -1) -> dict:
    """
    패킷 레코드를 세션 단위로 집계합니다.
    label: 0=정상, 1=사기, -1=미라벨(실시간 수신 시)
    """
    features = calculate_features(rtp_records)
    if features is None:
        return None

    return {
        "session_id"  : session_id,
        "avg_latency" : features["avg_latency"],
        "avg_jitter"  : features["avg_jitter"],
        "iat_variance": features["iat_variance"],
        "packet_loss" : features["packet_loss"],
        "seq_gap_rate": features["seq_gap_rate"],
        "label"       : label,
    }


# ──────────────────────────────────────────────
# 4. PCAP 파일 처리 (메인 진입점)
# ──────────────────────────────────────────────

def process_pcap(pcap_path: str, label: int = -1) -> list:
    """
    PCAP 파일 1개를 처리해 세션 레코드 리스트를 반환합니다.

    label:
        0  → 정상 (normal.pcap 처리 시)
        1  → 사기  (fraud.pcap  처리 시)
       -1  → 미라벨 (실시간 업로드)

    반환값:
        [{"session_id": ..., "avg_latency": ..., ...}, ...]
    """
    if not os.path.exists(pcap_path):
        print(f"[ERROR] 파일 없음: {pcap_path}")
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[ERROR] PCAP 읽기 실패: {e}")
        return []

    # SSRC 별로 패킷 분류 (SSRC = 세션 식별자)
    sessions: dict = {}

    for pkt in packets:
        if not pkt.haslayer(UDP):
            continue

        udp   = pkt[UDP]
        sport = udp.sport
        dport = udp.dport

        # RTP 포트 범위 필터
        if not (RTP_PORT_MIN <= sport <= RTP_PORT_MAX or
                RTP_PORT_MIN <= dport <= RTP_PORT_MAX):
            continue

        payload = bytes(udp.payload)
        rtp     = parse_rtp_header(payload)
        if rtp is None:
            continue

        ssrc = rtp["ssrc"]
        if ssrc not in sessions:
            sessions[ssrc] = []

        sessions[ssrc].append({
            "seq_num"     : rtp["seq_num"],
            "timestamp"   : rtp["timestamp"],
            "arrival_time": float(pkt.time),
        })

    # ── SIP 신호 패킷만 있고 RTP가 없는 경우 ──
    # (이안님 PCAP처럼 RTP 없이 SIP만 있을 때 → SIP 패킷으로 대체 추출)
    if not sessions:
        print(f"[INFO] RTP 패킷 없음 → SIP UDP fallback 시도: {pcap_path}")
        return _fallback_sip_session(packets, pcap_path, label)

    # 세션 집계
    results = []
    base    = os.path.splitext(os.path.basename(pcap_path))[0]

    for idx, (ssrc, records) in enumerate(sessions.items()):
        if len(records) < 5:   # 너무 짧은 세션 제외
            continue
        session_id = f"{base}_ssrc{ssrc}_{idx}"
        row = aggregate_session(records, session_id, label)
        if row:
            results.append(row)

    print(f"[OK] {pcap_path}: 세션 {len(results)}개 추출")
    return results


# ──────────────────────────────────────────────
# 4-1. SIP 전용 PCAP fallback (이안님 파일 대비)
# ──────────────────────────────────────────────

def _fallback_sip_session(packets, pcap_path: str, label: int) -> list:
    """
    RTP 없이 SIP UDP 패킷만 있는 경우,
    UDP 패킷 전체를 하나의 세션으로 간주해 IAT 기반 특징을 추출합니다.
    """
    udp_packets = [p for p in packets if p.haslayer(UDP)]
    if len(udp_packets) < 5:
        print(f"[WARN] UDP 패킷 부족 ({len(udp_packets)}개): {pcap_path}")
        return []

    records = []
    for i, pkt in enumerate(udp_packets):
        records.append({
            "seq_num"     : i,
            "timestamp"   : int(float(pkt.time) * CLOCK_RATE),
            "arrival_time": float(pkt.time),
        })

    base       = os.path.splitext(os.path.basename(pcap_path))[0]
    session_id = f"{base}_sip_fallback"
    row        = aggregate_session(records, session_id, label)

    if row:
        print(f"[OK] SIP fallback 세션 1개 추출: {session_id}")
        return [row]
    return []


# ──────────────────────────────────────────────
# 5. 여러 PCAP → CSV 일괄 변환
# ──────────────────────────────────────────────

def batch_pcap_to_csv(
    normal_pcap: str,
    fraud_pcap : str,
    output_csv : str = "data/processed/sessions.csv"
) -> pd.DataFrame:
    """
    정상/사기 PCAP 2개를 처리해 하나의 CSV로 저장합니다.
    """
    rows = []
    rows += process_pcap(normal_pcap, label=0)
    rows += process_pcap(fraud_pcap,  label=1)

    if not rows:
        print("[ERROR] 추출된 세션 없음. PCAP 파일을 확인하세요.")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    print(f"[저장] {output_csv} ({len(df)}개 세션)")
    return df


# ──────────────────────────────────────────────
# CLI 실행
# ──────────────────────────────────────────────

if __name__ == "__main__":
    df = batch_pcap_to_csv(
        normal_pcap="data/raw/normal.pcap",
        fraud_pcap ="data/raw/fraud.pcap",
        output_csv ="data/processed/sessions.csv",
    )
    if not df.empty:
        print("\n[미리보기]")
        print(df.to_string(index=False))
