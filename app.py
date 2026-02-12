import sqlite3
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# DB 연결 함수 (반복되는 코드를 줄이기 위해 만듦)
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # 컬럼 이름으로 데이터 조회 가능하게 설정
    return conn

# 1. 메인 화면 (대시보드)
@app.route('/')
def index():
    return render_template('index.html')

# 2. [API] 저장된 모든 세션 정보 가져오기 (GET)
@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    conn = get_db_connection()
    sessions = conn.execute('SELECT * FROM call_session ORDER BY created_at DESC').fetchall()
    conn.close()
    
    # DB 결과를 JSON(데이터 덩어리)으로 변환
    sessions_list = [dict(row) for row in sessions]
    return jsonify(sessions_list)

# 3. [API] AI 모델이 분석 결과를 보낼 때 받는 곳 (POST)
# 나중에 광준이가 이 주소로 데이터를 쏠 거야!
@app.route('/api/analyze', methods=['POST'])
def receive_analysis():
    data = request.json
    # 지금은 데이터를 받았다고 로그만 띄우고(print), 실제 저장은 3주차에 구현할게
    print(f"📩 AI 모델로부터 데이터 수신: {data}")
    return jsonify({"status": "success", "message": "데이터 수신 완료!"})

if __name__ == '__main__':
    print("🔥 서버가 실행되었습니다! http://127.0.0.1:5000")
    socketio.run(app, debug=True)