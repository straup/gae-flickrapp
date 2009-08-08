#!/usr/bin/env python

import wsgiref.handlers
from google.appengine.ext import webapp

# Please see comments in HelloWorld/__init__.py

import HelloWorld

if __name__ == '__main__':

  handlers = [
    ('/', HelloWorld.MainApp),
    ('/signout', HelloWorld.Signout),
    ('/signin', HelloWorld.Signin),    
    ('/auth', HelloWorld.TokenDance),
    ]

  application = webapp.WSGIApplication(handlers, debug=True)
  wsgiref.handlers.CGIHandler().run(application)
