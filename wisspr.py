import os
from flask import Flask, request, session, url_for, abort, render_template, \
flash, g, redirect
from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import security
from gevent import monkey
from socketio.server import SocketIOServer

monkey.patch_all

# configiration
DATABASE = 'wisspr.db'
DEBUG = True
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)

# Checks whether or not we are running in the production or development environment.
# In production, will use PostgreSQL. In development, will use sqlite3.
if not os.environ.has_key('DATABASE_URL'):
        os.environ['DATABASE_URL'] = 'sqlite:////tmp/dev.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
db = SQLAlchemy(app)

####################################################################################

#################################### ROUTES ########################################

@app.route('/')
def home():
	user = None
	if "username" in session:
		return render_template('home.html', user = get_user(session["username"]))
	return render_template('home.html', user = user)

@app.route('/login', methods=["GET", "POST"])
def login():
	error = None
	if request.method == 'POST':
		if authenticate(request.form["user"], request.form["password"]):
			session['username'] = request.form["user"]
			return redirect(url_for('home'))
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

@app.route('/logout')
def logout():
	session.pop('username', None)
	flash('You were logged out')
	return redirect(url_for('home'))

@app.route('/signup', methods=["GET", "POST"])
def signup():
	error = None
	# If you're simply trying to load the signup page
	if request.method == 'GET':
		return render_template('signup.html')
	# If you've attempted to signup
	elif request.method == 'POST':
		if not security.safe_str_cmp(request.form["password"],request.form["pass_confirm"]):
			return "Passwords must match!"
		elif not user_exists(request.form["user"]):
			# Creates a user object with this username and password hash
			user = User(request.form["user"], encrypt(request.form["password"]))
			# Adds this user to the database
			db.session.add(user)
			db.session.commit()

			return redirect(url_for('home'))

	return render_template('signup.html', error=error)

####################################################################################

############################### HELPER FUNCTIONS ###################################

# validates login (for login)
def authenticate(username, password):
	user = User.query.filter_by(username=username).first()
	if user and security.check_password_hash(user.password_hash, password):
		return True
	return False

# validates uniqueness (for signup)
def user_exists(username):
	return True if get_user(username) else False

def encrypt(string):
	return security.generate_password_hash(string)

# pulls the user with this name
def get_user(username):
	return User.query.filter_by(username=username).first()

###################################################################################

################################# MODEL CLASSES ###################################

# User class that is to be stored in the database by SQLAlchemy
class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True)
	password_hash = db.Column(db.String(120))

	def __init__(self, username, password_hash):
		self.username = username
		self.password_hash = password_hash

	def __repr__(self):
		return '<Name %r>' % self.username

if __name__ == "__main__":
	app.run(host="0.0.0.0")
	SocketIOServer(
        ('', app.config['PORT']), 
        app,
        resource="socket.io").serve_forever()
