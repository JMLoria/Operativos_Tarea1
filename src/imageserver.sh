#!/bin/bash
### BEGIN INIT INFO
# Provides:          imageserver
# Required-Start:    $network 
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start ImageServer TCP Daemon
### END INIT INFO

DAEMON="$(dirname "$0")/imageserver"
PIDFILE="$(dirname "$0")/imageserver.pid"
CONFIG="$(dirname "$0")/etc/server.conf"
LOGFILE="$(dirname "$0")/imageserver_data/server.log"

start() {
    echo "Starting ImageServer..."
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "Already running (PID $(cat $PIDFILE))."
        exit 1
    fi
    nohup $DAEMON $CONFIG >> $LOGFILE 2>&1 &
    echo $! > $PIDFILE
    echo "Started (PID $(cat $PIDFILE))."
}

stop() {
    echo "Stopping ImageServer..."
    if [ ! -f "$PIDFILE" ]; then
        echo "Not running"
        exit 1
    fi
    kill $(cat "$PIDFILE") && rm -f "$PIDFILE"
    echo "Stopped."
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "ImageServer is running (PID $(cat "$PIDFILE"))."
    else
        echo "ImageServer is not running."
    fi
}

restart() {
    stop 
    sleep 1
    start
}

case "$1" in 
    start) start ;;
    stop) stop ;;
    status) status ;;
    restart) restart ;;
    *) echo "Usage: $0 {start|stop|restart}" ;;
esac
