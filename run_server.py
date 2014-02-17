import sys
from wisspr import app
from gevent import monkey
from socketio.server import SocketIOServer


monkey.patch_all()
PORT = 5000

if __name__ == '__main__':
	print 'Listening on http://127.0.0.1:%s' % PORT
	try:
		SocketIOServer(('', PORT), app, resource="socket.io").serve_forever()
	except KeyboardInterrupt:
		# Note: make sure to use gevent 1.0 as apparently SystemExit does not exit
		# the process in earlier versions
		sys.exit()
