import os
from flask import Flask, request, session, url_for, abort, render_template, \
flash, g, redirect, Response
from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import security

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
		return render_template('home.html', user = get_user_by_name(session["username"]))
	return render_template('home.html', user = user)

@app.route('/login', methods=["GET", "POST"])
def login():
	error = None
	if request.method == 'POST':
		if authenticate(request.form["user"], request.form["password"]):
			session['username'] = request.form["user"]
			get_user_by_name(session['username']).online_status = True
			return redirect(url_for('home'))
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

@app.route('/logout')
def logout():
	if "username" in session:
		get_user_by_name(session['username']).online_status = False
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

<<<<<<< HEAD
@app.route('/addfriend', methods=["POST"])
def add_friend():
	if "username" in session and get_user_by_name(request.form["friend"]):
		user = get_user_by_name(session["username"])
		# Creates a friend and stores it in db using a one-to-many relationship
		friend = Friend(user.id, request.form["friend"])
		db.session.add(friend)
		db.session.commit()
	return redirect(url_for('home'))

@app.route('/socket.io/<path:remaining>')
def socketio(remaining):
    try:
        socketio_manage(request.environ, {'/chat': ChatNamespace}, request)
    except:
        app.logger.error("Exception while handling socketio connection",
                         exc_info=True)
    return Response()

=======
>>>>>>> a801d4723bab6093c5f00283aad8d06a00379ec4
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
	isOnline = False

	def __init__(self, friend_of, name):
		self.friend_of = friend_of
		self.name = name
		self.isOnline = get_user_by_name(name).online_status

	def __repr__(self):
		return '%r' % self.name


# TODO: Implement "conversation" class

class ChatNamespace(BaseNamespace):
    def initialize(self):
        self.logger = app.logger
        self.log("Socketio session started")

    def log(self, message):
        self.logger.info("[{0}] {1}".format(self.socket.sessid, message))

    def recv_connect(self):
        self.log("New connection")

    def recv_disconnect(self):
        self.log("Client disconnected")

    def on_join(self, name):
        self.log("%s joined chat" % user.username)
        return True, name

    def on_message(self, message):
    	self.log('got a message: %s' % message)
    	return True, message

if __name__ == "__main__":
	app.run(host="0.0.0.0")
