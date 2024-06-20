from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from cryptography.fernet import Fernet
import os
import base64

# Configuration
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'uploads'

# App initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Email configuration for Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password_or_app_password'

# Extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    verification_code = db.Column(db.String(6), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_key = db.Column(db.String(44), nullable=False)  # 44 characters for base64 encoded Fernet key

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utils
def generate_key():
    return Fernet.generate_key()

def encrypt_file(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_file(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_verification_code():
    return base64.urlsafe_b64encode(os.urandom(4)).decode('utf-8')[:6]

def send_verification_email(user, verification_code):
    msg = Message('Email Verification', sender='amanfarmahan22@gmail.com', recipients=[user.email])
    msg.body = f'Your verification code is: {verification_code}'
    mail.send(msg)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use. Choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered. Please use a different email address.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        verification_code = generate_verification_code()
        new_user = User(username=username, email=email, password=hashed_password, verification_code=verification_code)
        db.session.add(new_user)
        db.session.commit()
        
        send_verification_email(new_user, verification_code)
        
        return redirect(url_for('verify_code'))  # Redirect to verification page
    
    # Print out form errors for debugging
    if form.errors:
        print(form.errors)
    
    return render_template('register.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        verification_code = request.form.get('verification_code')
        user = User.query.filter_by(verification_code=verification_code).first()
        if user:
            flash('Verification successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            error = 'Wrong verification code. Please try again.'
            return render_template('verify.html', error=error)
    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Check your email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', name=current_user.username, files=user_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        try:
            key = generate_key()
            encrypted_data = encrypt_file(file.read(), key)
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
            new_file = File(filename=filename, user_id=current_user.id, encryption_key=key.decode())
            db.session.add(new_file)
            db.session.commit()
            flash('File uploaded successfully', 'success')
        except Exception as e:
            flash(f'Error during file upload: {e}', 'danger')
    else:
        flash('File type not allowed', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_record = File.query.filter_by(filename=filename, user_id=current_user.id).first()
    if file_record:
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = decrypt_file(encrypted_data, file_record.encryption_key.encode())
            decrypted_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], 'decrypted_' + filename)
            with open(decrypted_filepath, 'wb') as f:
                f.write(decrypted_data)
            return send_from_directory(current_app.config['UPLOAD_FOLDER'], 'decrypted_' + filename, as_attachment=True)
    flash('File not found or access denied', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.cli.command('init-db')
def init_db():
    with app.app_context():
        db.create_all()
        print('Initialized the database.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database is created when running the app
    app.run(debug=True, port=8000)
