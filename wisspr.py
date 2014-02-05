from flask import Flask, render_template
from models import db

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
	if request.method == "POST":
		if authenticate(request.form['user'], request.form['password']):
			return request.form['user']
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

#def authenticate(user, password):
	#encrypted_password = encrypt(password)
	#if 

if __name__ == "__main__":
	app.run(host="0.0.0.0")