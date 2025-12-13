from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = 'dev_key_secret_123' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_life.db'

db = SQLAlchemy(app)

# --- LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

# --- DATABASE MODEL ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
#                ROUTES
# ==========================================

# 1. LOGIN / SIGNUP PAGE
@app.route('/')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('home'))
    else:
        flash('Invalid email or password. Please try again.', 'error')
        return redirect(url_for('login_page'))

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')

    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email already exists. Please log in.', 'error')
        return redirect(url_for('login_page'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(email=email, password=hashed_password, first_name=first_name, last_name=last_name)
    
    db.session.add(new_user)
    db.session.commit()
    
    flash('Account created successfully! Please sign in.', 'success')
    return redirect(url_for('login_page'))

# 2. DASHBOARD
@app.route('/home')
@login_required
def home():
    return render_template('home.html', user=current_user)

# 3. FEATURE PAGES (Connecting your links)
@app.route('/expense')
@login_required
def expense():
    return render_template('expense.html', user=current_user)

@app.route('/focus')
@login_required
def focus():
    return render_template('focus.html', user=current_user)

@app.route('/skill')
@login_required
def skill():
    return render_template('skill.html', user=current_user)

@app.route('/exercise')
@login_required
def exercise():
    return render_template('exercise.html', user=current_user)

# 4. LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))
# --- Add this Missing Route ---
@app.route('/mission')
def mission():
    return render_template('mission.html')

if __name__ == '__main__':
    app.run(debug=True)