from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import boto3
from botocore.exceptions import NoCredentialsError


S3_BUCKET = 'S3_BUCKET_NAME'
S3_REGION = 'S3_REGION'
S3_ACCESS_KEY = 'S3_ACCESS_KEY'
S3_SECRET_KEY = 'S3_SECRET_KEY'

ALLOWED_EXTENSIONS = {'png', 'jpg'}


s3 = boto3.client('s3', aws_access_key_id=S3_ACCESS_KEY, aws_secret_access_key=S3_SECRET_KEY, region_name=S3_REGION)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__, instance_path='/tmp')
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', "postgresql+psycopg2://DATABASE_URI")
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SESSION_COOKIE_SECURE'] = True  # 僅通過 HTTPS 傳輸
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 禁止 JavaScript 訪問 Cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 防止跨站請求
db = SQLAlchemy()
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)  # 增加長度
    avatar = db.Column(db.String(300))  # 存儲 URL 的 String 類型
    messages = db.relationship('Message', backref='user', lazy=True)  # Relationship to Message

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_avatar = db.Column(db.String(150), nullable=True)  # 新增欄位儲存頭貼路徑
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to User

# Initialize app with extension
db.init_app(app)
# Create database within app context
# app.app_context().push()
# db.create_all()
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    messages = Message.query.all()
    return render_template('home.html', messages=messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('註冊成功！請登入。')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # 每分鐘最多 5 次請求
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('登入成功！')
            return redirect(url_for('profile'))
        flash('登入失敗，請檢查帳號或密碼。')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('已登出。')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('請先登入。')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user_messages = Message.query.filter_by(username=user.username).all()
    if request.method == 'POST':
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and allowed_file(avatar.filename):
                filename = secure_filename(avatar.filename)
                try:
                    # 上傳檔案到 S3
                    s3.upload_fileobj(
                        avatar,
                        S3_BUCKET,
                        filename,
                        ExtraArgs={'ACL': 'public-read', 'ContentType': avatar.content_type}
                    )
                    # 儲存檔案的 S3 URL
                    new_avatar_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"
                    user.avatar = new_avatar_url
                    # 更新所有與該用戶相關的消息的 user_avatar
                    for message in user.messages:
                        message.user_avatar = new_avatar_url
                    db.session.commit()
                    flash('頭貼更新成功！')
                except NoCredentialsError:
                    flash('無法上傳檔案，請檢查 S3 配置。')
            else:
                flash('僅允許上傳 .png 和 .jpg 檔案。')
    return render_template('profile.html', user=user, user_messages=user_messages)

@app.route('/message', methods=['POST'])
def message():
    if 'user_id' not in session:
        flash('請先登入。')
        return redirect(url_for('login'))
    content = request.form['content']
    user = User.query.get(session['user_id'])  # 取得目前登入的使用者
    message = Message(username=session['username'], content=content, user_avatar=user.avatar, user_id=user.id)
    db.session.add(message)
    db.session.commit()
    flash('留言成功！')
    return redirect(url_for('home'))

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        flash('請先登入。')
        return redirect(url_for('login'))
    message = Message.query.get_or_404(message_id)
    if message.username != session['username']:
        flash('您無權刪除此留言。')
        return redirect(url_for('profile'))
    db.session.delete(message)
    db.session.commit()
    flash('留言已刪除。')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    if not os.path.exists('static/uploads'):
        os.makedirs('static/uploads')
    db.create_all()
    app.run(debug=True)