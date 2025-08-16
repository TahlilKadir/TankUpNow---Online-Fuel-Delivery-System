from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Example: Email field
    phone = db.Column(db.String(20), nullable=True)  # Example: Phone number
    role = db.Column(db.String(50), nullable=False)


class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    license_plate = db.Column(db.String(50), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('vehicles', lazy=True))
    
    def __repr__(self):
        return f'<Vehicle {self.make} {self.model} {self.year}>'


# Home page redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Query the user from the database
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Store the username in session
            session['username'] = user.username
            session['role'] = user.role  # Store the user's role in session
            
            # Redirect based on role
            if user.role == 'user':
                return redirect(url_for('dashboard'))
            elif user.role == 'driver':
                return redirect(url_for('dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')


# Sign-up route
@app.route('/signup', methods=['GET', 'POST'])

def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
        else:
            # Create a new user
            new_user = User(username=username, password=hashed_password, email=email, phone=phone, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()

        if request.method == 'POST':
            # Get the updated data from the form
            email = request.form['email']
            phone = request.form['phone']
            
            # Update the user's information
            user.email = email
            user.phone = phone

            # Commit the changes to the database
            db.session.commit()

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        # Render the profile page with the current user details
        return render_template('profile.html', user=user)

    else:
        flash('Please log in to access your profile.', 'info')
        return redirect(url_for('login'))

@app.route('/view_profile')
def view_profile():
    if 'username' in session:
        # Fetch the user data from the database based on the username in the session
        user = User.query.filter_by(username=session['username']).first()
        
        if user:
            return render_template('view_profile.html', user=user)
        else:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
    else:
        flash('Please log in to view your profile.', 'info')
        return redirect(url_for('login'))


# Dashboard route (requires login)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        
        if user.role == 'user':
            return render_template('dashboard_user.html', username=user.username)
        elif user.role == 'driver':

            if user:
                # Get the list of vehicles associated with the driver
                vehicles = Vehicle.query.filter_by(user_id=user.id).all()
                
            else:
                flash('Driver not found.', 'error')
                return redirect(url_for('login'))
            return render_template('dashboard_driver.html', driver=user, vehicles=vehicles)
        elif user.role == 'admin':
            return render_template('dashboard_admin.html', username=user.username)
        else:
            flash('Invalid user role', 'error')
            return redirect(url_for('logout'))
    else:
        flash('You need to log in first.', 'info')
        return redirect(url_for('login'))


@app.route('/register_vehicle', methods=['GET', 'POST'])


@app.route('/register_vehicle', methods=['GET', 'POST'])
def register_vehicle():
    if 'username' in session and session['role'] == 'driver':
        if request.method == 'POST':
            # Retrieve form data
            vehicle_make = request.form['make']
            vehicle_model = request.form['model']
            vehicle_year = request.form['year']
            vehicle_license_plate = request.form['license_plate']
            user_id = User.query.filter_by(username=session['username']).first().id

            # Try to create a new vehicle entry
            try:
                new_vehicle = Vehicle(make=vehicle_make, model=vehicle_model, year=vehicle_year,
                                      license_plate=vehicle_license_plate, user_id=user_id)
                db.session.add(new_vehicle)
                db.session.commit()

                flash('Vehicle registered successfully!', 'success')
                return redirect(url_for('dashboard'))  # Redirect to the driver dashboard
            except IntegrityError:
                db.session.rollback()  # Rollback the transaction if there's a duplicate error
                flash('This license plate is already registered. Please use a different license plate.', 'error')
                return redirect(url_for('register_vehicle'))

        return render_template('register_vehicle.html')
    else:
        flash('You must be a driver to register a vehicle.', 'error')
        return redirect(url_for('login'))  # Redirect to login if not a driver

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True) 


