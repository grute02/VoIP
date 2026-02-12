import sqlite3

def init_db():
    # database.db 라는 파일 이름으로 DB 연결
    connection = sqlite3.connect('database.db')
    
    # schema.sql 파일을 읽어서 실행 (encoding='utf-8' 추가!)
    with open('schema.sql', encoding='utf-8') as f:
        connection.executescript(f.read())
    
    connection.commit()
    connection.close()
    print("✅ 데이터베이스(database.db) 생성 완료!")

if __name__ == '__main__':
    init_db()