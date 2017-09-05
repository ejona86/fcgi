#!/usr/bin/env python2

import sys
from wsgiref.handlers import CGIHandler
from flup.server.fcgi import WSGIServer

def app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return ['Hello from Python\n']

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'cgi':
        CGIHandler().run(app)
    else:
        WSGIServer(app, bindAddress='../app-py.socket').run()
