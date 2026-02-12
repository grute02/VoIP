from flask import Flask, render_template
from flask_socketio import SocketIO

# 1. Flask 앱 생성
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

# 2. SocketIO(실시간 통신) 연결
socketio = SocketIO(app)

# 3. 메인 화면 라우팅 (누가 접속하면 index.html 보여주기)
@app.route('/')
def index():
    return render_template('index.html')

# 4. 서버 실행
if __name__ == '__main__':
    print("🔥 서버가 실행되었습니다! http://127.0.0.1:5000 로 접속하세요.")
    socketio.run(app, debug=True)