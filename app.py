from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Database setup
db = SQLAlchemy(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# Models
class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        message = request.form.get('message')
        if message and len(message.strip()) > 0:
            new_suggestion = Suggestion(message=message.strip())
            db.session.add(new_suggestion)
            db.session.commit()
            flash('Your suggestion has been submitted anonymously!', 'success')
            return redirect(url_for('submit'))
        else:
            flash('Please enter a message', 'error')
    return render_template('submit.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('admin_login.html')


@app.route('/admin/clear', methods=['POST'])
@login_required
def clear_suggestions():
    try:
        # Delete all suggestions
        num_deleted = db.session.query(Suggestion).delete()
        db.session.commit()
        flash(f'Successfully deleted {num_deleted} suggestions', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error clearing suggestions', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('reset_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('reset_password'))
            
        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('reset_password'))
            
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('reset_password'))
            
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('reset_password.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    suggestions = Suggestion.query.order_by(Suggestion.timestamp.desc()).all()
    today = datetime.now().date()
    today_count = Suggestion.query.filter(
        db.func.date(Suggestion.timestamp) == today
    ).count()
    return render_template('admin_dashboard.html', 
                         suggestions=suggestions,
                         today_count=today_count)

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

# Initial setup
def create_tables():
    with app.app_context():
        db.create_all()

def create_admin():
    with app.app_context():
        if not Admin.query.first():
            admin = Admin(username='admin')
            admin.set_password('admin123')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("Default admin created. Username: admin, Password: admin123")

if __name__ == '__main__':
    create_tables()
    create_admin()
    app.run(debug=True)