import mysql.connector
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import logging

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# Log ayarları
log_file_path = os.path.join(os.getcwd(), 'netpulse_auth.log')
logger = logging.getLogger('netpulse_auth')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(log_file_path)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# MySQL bağlantı bilgileri
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'seray5216',
    'database': 'netpulse_db'
}

def create_database_and_tables():
    """Veritabanını ve tabloları oluştur"""
    try:
        conn = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )
        cursor = conn.cursor()
        
        # Veritabanını oluştur
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['database']}")
        cursor.execute(f"USE {db_config['database']}")
        
        # Kullanıcı tablosunu oluştur
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullname VARCHAR(100) NOT NULL,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tarama geçmişi tablosunu oluştur
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                scan_type ENUM('ip','mac','os','services') NOT NULL,
                scan_data JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX(user_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        
        conn.commit()
        logger.info("Veritabanı ve tablolar başarıyla oluşturuldu")
    except mysql.connector.Error as err:
        logger.error(f"MySQL hatası: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def get_db_connection():
    """Veritabanı bağlantısı oluştur"""
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        logger.error(f"MySQL bağlantı hatası: {err}")
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Kullanıcı giriş işlemi"""
    error = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        if not conn:
            error = "Veritabanı bağlantısı kurulamadı"
            return render_template('login.html', error=error)
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            session['fullname'] = user['fullname']
            session['user_id'] = user['id']
            logger.info(f"Kullanıcı giriş yaptı: {username}")
            return redirect(url_for('index'))
        else:
            error = 'Kullanıcı adı veya şifre hatalı'
            logger.warning(f"Hatalı giriş denemesi: {username}")
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Kullanıcı kayıt işlemi"""
    error = None
    
    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            error = 'Şifreler eşleşmiyor'
            return render_template('register.html', error=error)
        
        # Şifreyi hash'le
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        if not conn:
            error = "Veritabanı bağlantısı kurulamadı"
            return render_template('register.html', error=error)
        
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (fullname, username, password) VALUES (%s, %s, %s)",
                (fullname, username, hashed_password)
            )
            conn.commit()
            logger.info(f"Yeni kullanıcı kaydedildi: {username}")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            error = 'Bu kullanıcı adı zaten kullanılıyor'
            logger.warning(f"Kullanıcı adı çakışması: {username}")
        except mysql.connector.Error as err:
            error = f'Kayıt yapılamadı: {str(err)}'
            logger.error(f"Kullanıcı kaydı hatası: {err}")
        finally:
            cursor.close()
            conn.close()
    
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    """Kullanıcı çıkış işlemi"""
    username = session.get('username', 'Bilinmeyen kullanıcı')
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('fullname', None)
    logger.info(f"Kullanıcı çıkış yaptı: {username}")
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Ana sayfa yönlendirmesi"""
    if 'logged_in' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_database_and_tables()
    app.run(debug=True, host='0.0.0.0', port=5000) 