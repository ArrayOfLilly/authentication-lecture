import sqlalchemy
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB with the UserMixin
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    if current_user.is_authenticated:
        logged_in = True
        print(logged_in)
        return render_template("index.html", logged_in=logged_in, name=current_user.name)
    else:
        logged_in = False
        print(logged_in)
    return render_template("index.html", logged_in=logged_in)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=hashed_password,
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash(f'Another new_user with this email ({new_user.email}) is already registered.')
            return render_template("register.html")

        # Log in and authenticate new_user after adding details to database.
        login_user(new_user)
        return redirect(url_for('secrets', name=request.form['name']))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find user by email entered.
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash("This user doesn't exist. Please, try again!")
            return redirect(url_for('login'))
        # Check stored password hash against entered password hashed.
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
        else:
            flash("Incorrect password. Please, try again!")
            print(user.email)
            return render_template('login.html', email=user.email)

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    # name = request.args.get('name')
    
    # Flask Login Provided Proxy:
    name = current_user.name
    return render_template("secrets.html", name=name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<path:file_name>')
@login_required
def download(file_name):
    return send_from_directory('static/files', file_name, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
