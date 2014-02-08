import os
from flask import Flask, request, session, url_for, abort, render_template, \
flash, g, redirect, Response
from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import security
import datetime

# configiration
DATABASE = 'wisspr.db'
DEBUG = True
SECRET_KEY = 'development key'
PORT = 5000

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
		user = get_user_by_name(session["username"])
	return render_template('home.html', user = user)

@app.route('/login', methods=["GET", "POST"])
def login():
	error = None
	if request.method == 'POST':
		if authenticate(request.form["user"], request.form["password"]):
			session['username'] = request.form["user"]
			get_user_by_name(session['username']).online_status = True
			db.session.commit()
			return redirect(url_for('home'))
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

@app.route('/logout')
def logout():
	if "username" in session:
		get_user_by_name(session['username']).online_status = False
		db.session.commit()
		session.pop('username')
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
			error = "Passwords must match"
		elif user_exists(request.form["user"]):
			error = "Username taken"
		else:
			# Creates a user object with this username and password hash
			user = User(request.form["user"], encrypt(request.form["password"]))
			# Adds this user to the database
			db.session.add(user)
			db.session.commit()

			return redirect(url_for('home'))

	return render_template('signup.html', error=error)

@app.route('/addfriend', methods=["POST"])
def add_friend():
	if "username" in session and get_user_by_name(request.form["friend"]):
		user = get_user_by_name(session["username"])
		# Creates a friend and stores it in db using a one-to-many relationship
		friend = Friend(user.id, request.form["friend"])
		db.session.add(friend)
		db.session.commit()
	return redirect(url_for('home'))

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
	return True if get_user_by_name(username) else False

def encrypt(string):
	return security.generate_password_hash(string)

# pulls the user with this name
def get_user_by_name(username):
	return User.query.filter_by(username=username).first()

# pulls the user with this id
def get_user_by_id(id):
	return User.query.get(id).first()

###################################################################################

################################# MODEL CLASSES ###################################

# User class that is to be stored in the database by SQLAlchemy
class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True)
	password_hash = db.Column(db.String(120))
	online_status = db.Column(db.Boolean, default = False)
	friends = db.relationship('Friend', backref='user', lazy='dynamic')
	conversations = db.relationship('Conversation', backref='owner', lazy='dynamic')

	def __init__(self, username, password_hash):
		self.username = username
		self.password_hash = password_hash

	def __repr__(self):
		return '<Name %r>' % self.username

# User's "friend" that includes
class Friend(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	friend_of = db.Column(db.Integer, db.ForeignKey('user.id'))
	name = db.Column(db.String(80))

	def __init__(self, friend_of, name):
		self.friend_of = friend_of
		self.name = name

	def __repr__(self):
		return '%r' % self.name

	def isOnline(self):
		return get_user_by_name(self.name).online_status

class Conversation(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	message = db.relationship('Message', backref='conversation', lazy='dynamic')
	name = db.Column(db.String(50))
	creator = db.Column(db.Integer)
	lastModified = dbColumn(db.DateTime)


	def __init__(self, conversationName):
		self.name=conversationName
		self.creator= owner.id
		self.updateTime()

	def updateTime(self):
		self.lastModified=datetime.datetime.now()






# TODO: Implement "conversation" class

if __name__ == "__main__":
	app.run(host="0.0.0.0")
