import os
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Setup the secret key for sessions and the SQLite database
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the User model with a role for admin/user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    address = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'

# Define the Complaint model with a status field and location
class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complaint_description = db.Column(db.Text, nullable=False)
    reason = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(255), nullable=False)  # Added location field
    proof_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Pending')  # Status like 'Pending', 'Resolved', etc.
    user = db.relationship('User', backref='complaints', lazy=True)

# Create tables in the database and create admin user if not exists
with app.app_context():
    db.create_all()

    # Check if admin user exists, if not create one
    admin = User.query.filter_by(username='admin', role='admin').first()
    if not admin:
        hashed_password = generate_password_hash('admin1234', method='pbkdf2:sha256')
        admin_user = User(
            username='admin',
            phone='1234567890',
            address='Admin Address',
            location='Admin Office',
            password=hashed_password,
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with username: admin and password: admin1234")

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        phone = request.form['phone']
        address = request.form['address']
        location = request.form['location']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(username=username, phone=phone, address=address, location=location, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    
    return render_template('register.html')

# Login Route for Users
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password', 403

    return render_template('login.html')

# Admin Login Route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = User.query.filter_by(username=username, role='admin').first()

        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect(url_for('admin_dashboard'))
        else:
            return 'Invalid admin username or password', 403

    return render_template('admin_login.html')

# User Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    complaints = Complaint.query.filter_by(user_id=user_id).all()

    return render_template('dashboard.html', user=user, complaints=complaints)

# Admin Dashboard Route
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    complaints = Complaint.query.all()
    users = User.query.all()
    return render_template('admin_dashboard.html', complaints=complaints, users=users)

# Logout Route for Users
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Logout Route for Admin
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))

# Submit Complaint Route (for Users)
@app.route('/submit_complaint', methods=['POST'])
def submit_complaint():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    complaint_description = request.form['complaint_description']
    reason = request.form['reason']
    location = request.form['location']  # Capture location
    proof = request.files.get('proof')

    proof_filename = None
    if proof:
        proof_filename = proof.filename
        # Ensure the static/proof directory exists
        proof_directory = 'static/proof'
        if not os.path.exists(proof_directory):
            os.makedirs(proof_directory)

        proof.save(os.path.join(proof_directory, proof_filename))

    # Create a new complaint entry with the location field
    new_complaint = Complaint(user_id=user_id, complaint_description=complaint_description, reason=reason,
                              location=location, proof_filename=proof_filename)
    db.session.add(new_complaint)
    db.session.commit()

    return redirect(url_for('dashboard'))

# View Complaint Status (for Users)
@app.route('/view_complaint/<int:complaint_id>')
def view_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    return render_template('view_complaint.html', complaint=complaint)

# Update Complaint Status (Admin only)
@app.route('/admin/update_status/<int:complaint_id>', methods=['POST'])
def update_status(complaint_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    complaint = Complaint.query.get(complaint_id)
    if complaint:
        complaint.status = request.form['status']  # Status is coming from a form select input
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return 'Complaint not found', 404

# Admin View User Profile
@app.route('/admin/view_user/<int:user_id>')
def view_user(user_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)
    complaints = Complaint.query.filter_by(user_id=user.id).all()
    return render_template('view_user_profile.html', user=user, complaints=complaints)

if __name__ == '__main__':
    app.run(debug=True)
