import sqlite3
from flask import Flask, request, session, url_for, abort, render_template, \
flash, g, redirect
from werkzeug import security
from contextlib import closing
import requests

# configiration
DATABASE = '/tmp/wisspr.db'
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'admin'
PASSWORD = 'default'

app = Flask(__name__)
app.config.from_object(__name__)
#app.config.from_envvar('WISSPR_SETTINGS', silent=True)

@app.route('/')
def home():
	return render_template('home.html')

@app.route('/login', methods=["GET", "POST"])
def login():
	error = None
	if request.method == 'POST':
		if authenticate(request.form["user"], request.form["password"]):
			session['logged_in'] = True
			return render_template('app.html', error=error)
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	flash('You were logged out')
	return redirect(url_for('home'))

@app.route('/signup', methods=["GET", "POST"])
def signup():
	error = None
	if request.method == 'GET':
		return render_template('signup.html')
	elif request.method == 'POST':
		if not security.safe_str_cmp(request.form["password"],request.form["pass_confirm"]):
			return "Passwords must match!"
		else:
			g.db.execute('insert into entries (username, password_hash) values (?, ?)',
				[request.form["user"], encrypt(request.form["password"])])
			g.db.commit()
			return redirect(url_for('home'))

	return render_template('signup.html', error=error)

def authenticate(user, password):
	cur = g.db.execute('select username, password_hash from entries where username = ?', 
		[user])
	rv = [dict(username=row[0], password_hash=row[1]) for row in cur.fetchall()]

	if rv:
		first = rv[0]
		if security.check_password_hash(first['password_hash'], password):
			return True
	return False

def encrypt(string):
	return security.generate_password_hash(string)	

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

def init_db():
	with closing(connect_db()) as db:
		with app.open_resource('schema.sql', mode='r') as f:
			db.cursor().executescript(f.read())
		db.commit()

@app.before_request
def before_request():
	g.db = connect_db();

@app.teardown_request
def teardown_request(exception):
	db = getattr(g, 'db', None)
	if db is not None:
		db.close()

if __name__ == "__main__":
	app.run(host="0.0.0.0")