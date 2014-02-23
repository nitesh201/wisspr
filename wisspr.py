from gevent import monkey; monkey.patch_all()
# import threading
# import os
from flask import Flask, request, session, url_for, abort, render_template, \
flash, g, redirect, Response
from sqlalchemy import create_engine, Table, Column, Integer, ForeignKey, String, Sequence, Boolean, DateTime
from sqlalchemy.orm import relationship, backref, sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from werkzeug import security
from socketio import socketio_manage
from socketio.namespace import BaseNamespace
import datetime

# configiration
DEBUG = True
SECRET_KEY = 'development key'
PORT = 5000

app = Flask(__name__)
app.config.from_object(__name__)

engine = create_engine('sqlite:///wisper.db', convert_unicode=True)
dbSession = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

#constructing Base
Base = declarative_base()
Base.query=dbSession.query_property()


def init_db():
	Base.metadata.create_all(bind=engine)

def  drop_db():
	Base.metadata.drop_all(bind=engine)
####################################################################################

#################################### ROUTES ########################################

@app.route('/')
def home():
	user = None
	if is_logged_in():

		user = get_user_by_name(session["username"])
		conversation = user.mostRecentConversation()
		if conversation:
			return redirect(url_for('show_messages', conversation_id=conversation.id))
	
	return render_template('home.html', user=user)

@app.route('/login', methods=["GET", "POST"])
def login():
	error = None
	if request.method == 'POST':
		if authenticate(request.form["user"], request.form["password"]):
			session['username'] = request.form["user"]
			get_user_by_name(session['username']).online_status = True
			dbSession.commit()
			return redirect(url_for('home'))
		else:
			error = 'Invalid username/password'

	return render_template('home.html', error=error)

@app.route('/logout')
def logout():
	if is_logged_in():
		get_user_by_name(session['username']).online_status = False
		dbSession.commit()
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
			#saves upon initializing
			User(request.form["user"], encrypt(request.form["password"]))
			return redirect(url_for('home'))

	return render_template('signup.html', error=error)

@app.route('/add_friend', methods=["POST"])
def add_friend():
	if is_logged_in() and get_user_by_name(request.form["friend"]):
		friender = get_user_by_name(session["username"])
		friended = get_user_by_name(request.form["friend"])
		
		##send friend request
		friender.sendFriendRequest(friended)
		##for now, automatically accept friend request for other person
		friended.acceptFriendRequest(friender)
		dbSession.commit()
	return redirect(url_for('home'))


@app.route('/messages/create/<friend>')
def create_conversation_with(friend):
	if is_logged_in:##should be is_logged_in()?
		user = get_user_by_name(session["username"])
		invitedFriend = get_user_by_name( friend )
		newConvo=user.openConversation([friend],invitedFriend.username)
		return redirect(url_for('show_messages', conversation_id = newConvo.id))
	return redirect(url_for('home'))


@app.route('/messages/show/<conversation_id>')
def show_messages(conversation_id):
	this_conversation = None
	user = None
	if is_logged_in():
		user = get_user_by_name(session["username"])
		for conversation in user.conversations:
			if conversation.id == int(conversation_id):
				this_conversation = conversation
	return render_template('home.html', user=user, conversation=this_conversation)

####################################################################################

############################### HELPER FUNCTIONS ###################################

# validates login (for login)
def authenticate(username, password):
	user = dbSession.query(User).filter_by(username=username).first()
	if user and security.check_password_hash(user.password_hash, password):
		return True
	return False

# validates uniqueness (for signup)
def user_exists(username):
	return True if get_user_by_name(username) else False

def encrypt(string):
	return security.generate_password_hash(string)

def get_user_by_name(usernameSearched):
	return dbSession.query(User).filter_by(username=usernameSearched).first()

def get_user_by_id(id):
	return dbSession.query(User).get(id)

def get_conversation_by_id(id):
	return dbSession.query(Conversation).get(id)

def is_logged_in():
	return "username" in session


def save_to_db(data):
	dbSession.add(data)
	dbSession.commit()


###################################################################################

################################# MODEL CLASSES ###################################

# Join table to model the User has many Conversations and Conversation has 
# many Users relationship

# tables
user_user = Table ('user_user',Base.metadata,
	Column('friender_id',Integer, ForeignKey('users.id'),primary_key=True),
	Column('requested_id',Integer, ForeignKey('users.id'),primary_key=True)
)

conversation_user = Table ('conversation_user',Base.metadata,
	Column('conversation_id',Integer, ForeignKey('conversations.id')),
	Column('user_id',Integer, ForeignKey('users.id'))
)



class User(Base):
	__tablename__ = 'users'
	id = Column(Integer, primary_key=True)#try deleting sequence
	username = Column(String(50), unique=True)
	sessid = Column(Integer, default=None)
	password_hash = Column(String(120))
	online_status = Column (Boolean, default= False)

	#friend requests are never eliminated
	friends = relationship( "User", secondary=user_user ,#may need default of to set as list...
				primaryjoin=(id==user_user.c.friender_id),
				secondaryjoin =(id==user_user.c.requested_id),
				backref='friendRequests'
	)

	conversations = relationship( 'Conversation', #may need to set default as list.
		 		secondary= conversation_user,
		 		backref = backref('users',lazy='dynamic')
	)

	##myConversations created in backreference


	def __init__ (self, name, pass_hash): 
		self.username=name
		self.password_hash=pass_hash
		save_to_db(self)

	def isOnline(self):
		return self.online_status

	def acceptFriendRequest(self, other):
		if ((other in self.friendRequests) 
			and (other not in self.friends)) : 
			self.friends.append(other)

	def sendFriendRequest(self, other):
		if ((other not in self.friendRequests) 
			and (other not in self.friends)) : 
			self.friends.append(other)

	def isFriendsWith(self,other):
		return ((other in self.friendRequests) and (other in self.friends))

	def openConversation(self, others, title):
		newConvo=Conversation(self,title)
		if (title != None ):
			newConvo.subject=title
		newConvo.add(self)
		for personUsername in others:
			personObj=dbSession.query(User).filter_by(username= personUsername).first()
			if self.isFriendsWith(personObj):
				newConvo.add(personObj)
		return newConvo

	def mostRecentConversation(self):
		most_recent = None
		for conversation in self.conversations:
			if not most_recent or conversation.lastModified > most_recent.lastModified:
				most_recent = conversation
		return most_recent


	def __repr__(self):
		return '<Name %r>' % self.username

class Conversation(Base):
	__tablename__ ='conversations'
	id= Column(Integer,primary_key=True)
	name=Column(String(50))
	creator_id= Column (Integer, ForeignKey('users.id'))
	lastModified = Column(DateTime)

	creator = relationship("User", backref=backref('myConversations', lazy='dynamic'))
	#messages = relationship('Message', backref=backref('conversation', lazy='dynamic'))

	def __init__(self, creator, conversationName):
		self.name=conversationName
		self.creator= creator #this is a User
		self.lastModified=datetime.datetime.now()
		save_to_db(self)

	def __repr__(self):
		return '<Conversation: %r>' % self.name

	def updateTime(self):
		self.lastModified=datetime.datetime.now()
		dbSession.commit()

	##this method does not work and is not used
	def add(self,newParticipant):
		self.users.append(newParticipant)
		dbSession.commit()


	def __repr__(self):
		return '<Conversation: %r>' % self.name

class Message(Base):
	__tablename__ ='messages'
	id = Column(Integer, primary_key=True)
	conversation_id = Column(Integer, ForeignKey('conversations.id'))
	sender_id = Column(Integer, ForeignKey('users.id'))
	data = Column(String(400))

	##try instead of lazy=dynamic "order_by=id"
	conversation = relationship("Conversation", backref=backref('messages', lazy='dynamic'))
	sender = relationship("User", backref=backref('messages', lazy='dynamic'))

	def __init__(self, conversation, data, sender):
		self.conversation = conversation#this is a Conversation object
		self.data = data
		self.sender = sender# this is a User Object
		save_to_db(self)

	def __repr__(self):
		return '<Message: %r>' % self.data

	def represent(self):
		return get_user_by_id(self.sender_id).username + ": " + self.data

	def poof(self): pass


#####################################################################################

################################### SOCKET STUFF ####################################

@app.route('/socket.io/<path:remaining>')
def socketio(remaining):
	try:
		socketio_manage(request.environ, {'/chat' : ChatNamespace}, request)
	except:
		app.logger.error("Exception while handling socketio connection", exc_info=True)
	return Response()

class ChatNamespace(BaseNamespace):
	def initialize(self):
		self.logger = app.logger
		self.log("Socketio session started")

	def log(self, message):
		self.logger.info("[{0}] {1}".format(self.socket.sessid, message))

	def on_open(self, user_id, conversation_id):
		user = get_user_by_id(user_id)
		conversation = get_conversation_by_id(conversation_id)
		user.sessid = self.socket.sessid
		dbSession.commit()

		if conversation not in user.conversations:
			return False

		self.user = user
		self.conversation = conversation
		self.log('Conversation {0} opened by {1}'.format(self.conversation.name, 
			user.username))
		self.session['conversation_id'] = self.conversation.id
		self.session['user_id'] = user.id
		return True

	def on_send_message(self, message):
		self.log('User message: {0}'.format(message))
		Message(self.conversation, message, self.user)
		self.send_all(message)
		return True

	def send_all(self, message):
		pkt = dict(type="event", 
				name='add_message', 
				args=[self.user.username, message], 
				endpoint=self.ns_name)
		for user in self.conversation.users:
			sessid = user.sessid
			socket = self.socket.server.get_socket(str(sessid))
			#must also check to make sure the other users aren't looking at different conversations...
			if (socket is not None ) and self.conversation.id == socket.session['conversation_id']:
				socket.send_packet(pkt)

	def on_poof(self, message, whole_conversation = False): 
		pass


if __name__ == "__main__":
	app.run(host="0.0.0.0")
