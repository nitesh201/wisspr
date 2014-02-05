from flask import Flask, render_template, request
import requests
from models import db, User

app = Flask(__name__)
app.config["DEBUG"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql://root:password@localhost/development'
db.init_app(app)

@app.route('/')
def home():
	return render_template('home.html')

@app.route('/testdb')
def testdb():
	if db.session.query("1").from_statement("SELECT 1").all():
		return 'It works.'
	else:
		return 'Something is broken.'

@app.route('/login', methods=["GET", "POST"])
def login():
	error = None
	if request.method == 'POST':
		if authenticate(request.form['email'], request.form['password']):
			return "OK"
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

@app.route('/signup', methods=["GET", "POST"])
def signup():
	if request.method == 'GET':
		return render_template('signup.html')
	elif request.method == 'POST':
		user = User.query.filter_by(email = request.form['email']).first()
		if user:
			return render_template('signup.html', error=
				"That email is already taken")
		else:
			return "SIGNED UP!"

def authenticate(user, password):
	return false
	#encrypted_password = encrypt(password)
	#if 

if __name__ == "__main__":
	app.run(host="0.0.0.0")