$(function() {

    var WEB_SOCKET_SWF_LOCATION = '/static/js/socketio/WebSocketMain.swf',
        socket = io.connect('/chat');

    socket.on('connect', function () {
        socket.emit('open', window.user_id, window.conversation_id);
        console.log("Connected!");
    });

    socket.on('add_message', message);

    socket.on('reconnect', function () {
        $('#lines').remove();
        message('System', 'Reconnected to the server');
    });

    socket.on('reconnecting', function () {
        message('System', 'Attempting to re-connect to the server');
    });

    socket.on('error', function (e) {
        message('System', e ? e : 'A unknown error occurred');
    });

    function message (from, msg) {
        $('#lines').append(from, ': ', msg, '<br>');
    }

    $(function () {
        $('#send').submit(function () {
            socket.emit('send message', $('#message').val());
            clear();
            return false;
        });

        function clear () {
            $('#message').val('').focus();
        }
    });

});