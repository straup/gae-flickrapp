#!/usr/bin/env python

import wsgiref.handlers

from google.appengine.ext import webapp
from google.appengine.ext import db
from django.utils import simplejson

from Flickr import API as flickr

import os
import binascii
import time
import datetime
import md5
import urllib
from urlparse import urlparse

#
#
#

class FlickrApp (webapp.RequestHandler) :
  
  """FlickrApp is a simple base class to use with Google App Engine (GAE)
  packages that allows you to use Flickr as a Single Sign On (SSO)
  provider and validation service. As an extra bonus you get a Flickr
  API Auth token in the process!

  Currently this class is designed (and tested) to work with the plain
  vanilla GAE/Django development environment. The next step is to ensure
  that is works with the AppDrop GAE/EC2 container.
  """
  
  def __init__ (self, api_key, api_secret) :

    """
    Create a new FlickrApp object.
    
    Remember, this class is not meant to be used on it's own. Rather
    it is a base class that you subclass in your own application. For
    example:

    	class MyFlickrApp (FlickrApp) :

          def init (self) :
            api_key = "this part is left to you"
            api_secret = "to squirt in to your application"

            FlickrApp.__init__(self, api_key, api_secret)
    """
    
    webapp.RequestHandler.__init__(self)
    
    self._api_key = api_key
    self._api_secret = api_secret
    
    self.api = flickr.API(self._api_key, self._api_secret)
    self.user = None

    self.perms_map = { 'read' : 1, 'write' : 2, 'delete' : 3 }

  def check_logged_in (self, min_perms=None) :

    """
    Check to see if the current user is logged in. If not, force
    them to re-authenticate your application via the Flickr API
    Auth flow.

    Logged in is defined as having valid 'ffo' and 'fft' cookies.
    
    'ffo' cookies are constantly renewed for 30 days with each page
    view and map the current user to a user in the FlickrUser database.
    If the cookie is not present or does not validate this method
    returns False.

    'fft' cookies last the duration of the browser session and are
    used to ensure that the user has a token with a minimum permissions
    set. This is done by calling the flickr.auth.checkToken method. If
    the token does not match this method returns False.

    If both cookies validate, the object's 'user' key will be set and
    the method will return True.

    For example:
    
    	class MyHandler (FlickrApp) :

          # Assume __init__ here...
          
          def get (self) :
            min_perms = 'read'
    
            if not self.check_logged_in(min_perms) :
              self.do_flickr_auth(min_perms)
              return
    
            self.response.out.write("Hi there %s" % self.user.username)
    """
    
    cookies = self.request.cookies

    if not cookies.has_key('ffo') :
      return False
    
    whoami = cookies['ffo'].split(":")

    if len(whoami) != 2 :
      return False
    
    users = db.GqlQuery("SELECT * FROM FlickrUser WHERE password = :1", whoami[1])

    if users.count() == 0 :
      return False

    self.user = users.get()

    if str(self.user.key()) != str(whoami[0]) :
      return False

    if min_perms :

      if cookies.has_key('fft') :

        # check that the cookie looks sane
        
        fft = self.generate_fft(self.user)

        if cookies['fft'] != fft :
          return False

        # check that the user token has
        # some minimum permissions

        need_perms = self.perms_map[min_perms]
        has_perms = self.user.perms

        if has_perms < need_perms :
          return False

      else :

        if not self.check_token(min_perms) :
          return False
          
    # Happy happy
    
    return True

  def do_flickr_auth (self, min_perms=None) :

    """
    This method will generate and redirect the user to the Flickr
    API Auth endpoint where the user will be prompted to approve
    your request for a Flickr token (with 'min_perms' permissions).
    """
  
    args = {'api_key' : self._api_key}

    redir = 'redir=%s' % urllib.quote(self.request.path)
    args['extra'] = redir

    # token-crumb, maybe?
    
    if min_perms:
      args['perms'] = min_perms

    sig = flickr.sign_args(self._api_secret, args)

    args['api_sig'] = sig

    query = urllib.urlencode(args)
    url = "http://www.flickr.com/services/auth/?%s" % query    

    self.redirect(url)

  def do_token_dance (self, perms=None) :

    """
    This is the method you should call from your 'auth' handler; that
    is the URL that you tell the Flickr API Auth flow to redirect to
    once a user has authed your application (in magic Flickr land).

    It will check for a 'frob' parameter and then call the Flickr API
    and exchange it for a valid Flickr Auth token.

    If something goes wrong it will return False, otherwise it will
    redirect the user to your application's root URL (where presumably
    you are calling 'checked_logged_in').
    
    For example:

    class TokenFrobHandler (FlickrApp) :

      # Assume __init__ here
      
      def get (self):  
        if not self.do_token_dance() :
          self.response.out.write("OH NOES! SOMETHING WENT WRONG!")
    
    """
    
    frob = self.request.get('frob')

    if not frob or frob == '' :
      return False

    extra = self.request.get('extra')
    e_params = {}
  
    if extra and extra != '' :
    	extra = urlparse(extra)
        e_params = dict([part.split('=') for part in extra[2].split('&')])

    # token-crumb, maybe?
    
    args = {'frob': frob, 'check_response' : True}
    rsp = self.api_call('flickr.auth.getToken', args)

    if not rsp :
    	return False
        
    token = rsp['auth']['token']['_content']
    name = rsp['auth']['user']['username']
    nsid = rsp['auth']['user']['nsid']
    perms = rsp['auth']['perms']['_content']
    user_perms = self.perms_map[perms]
    
    user = self.get_user_by_nsid(nsid)
      
    if not user :
      user_pswd = self.generate_password()
      
      user = FlickrUser()
      user.password = user_pswd
      user.token = token
      user.username = name
      user.nsid = nsid
      user.perms = user_perms
      user.put()
    else :

      user.token = token
      user.perms = user_perms
      user.username = name
      user.put()

    self.response.headers.add_header('Set-Cookie', self.ffo_cookie(user))
    self.response.headers.add_header('Set-Cookie', self.fft_cookie(user))    

    if e_params.has_key('redir') :
    	self.redirect(e_params['redir'])
    else :
  	self.redirect("/")

  def get_user_by_nsid (self, nsid) :

    """
    A helper method to return a FlickrUser object matching a given NSID.
    """
    
    users = db.GqlQuery("SELECT * FROM FlickrUser WHERE nsid = :1", nsid)

    if users.count() == 0 :
      return None

    return users.get()
        
  def api_call (self, method, args={}) :

    """
    A helper method to call the Flickr API and return a (simple)
    JSON object.

    If something goes wrong with the actual request, the method
    returns False.

    'args' are the arguments you want to pass to the method. There
    is one magic argument called 'check_response' which if True
    (the default is False) will cause the method to ensure that the
    API method returned 'stat=ok' returning False if it does not.
    """

    check_response = False
    
    if args.has_key('check_response') :
      check_response = args['check_response']
      del(args['check_response'])
      
    args['format'] = 'json'
    args['nojsoncallback'] = 1

    try :
      res = self.api.execute_method(method=method, args=args)
      json = simplejson.loads(res.read())
    except Exception:
      return None
    
    if check_response and json['stat'] != 'ok' :
      return None

    return json
  
  def check_token (self, min_perms) :

    """A helper methof to ensure that the currently logged in user's
    Flickr API auth token has permissions greater than or equal to
    'min_perms'.

    Returns True or False."""

    if not self.user :
      return False
    
    args = {'auth_token' : self.user.token, 'check_response' : True}
    rsp = self.api_call('flickr.auth.checkToken', args)

    if not rsp :
      return False
    
    perms = rsp['auth']['perms']['_content']
    nsid = rsp['auth']['user']['nsid']
    
    if nsid != self.user.nsid :
      return False

    need_perms = self.perms_map[min_perms]
    has_perms = self.perms_map[perms]

    if has_perms < need_perms :

      self.user.token = ''
      self.user.perms = 0
      self.user.put()
      
      return False

    return True
  
  def generate_ffo (self, user) :

    """A helper method to generate the value of the 'ffo' cookie for a user."""
    
    ffo = "%s:%s" % (user.key(), user.password)
    return ffo
  
  def ffo_cookie (self, user) :

    """A helper method to generate the 'ffo' cookie string for a user."""
    
    now = datetime.datetime.fromtimestamp(time.time())
    delta = datetime.timedelta(days=30)
    then = now + delta
    expires = then.strftime("%a, %e-%b-%Y %H:%M:%S GMT")

    ffo = self.generate_ffo(user)
    ffo_cookie = "ffo=%s; expires=%s" % (ffo, expires)
    return str(ffo_cookie)

  def generate_fft (self, user) :

    """A helper method to generate the value of the 'fft' cookie for a user."""
    
    hash = md5.new()
    hash.update("%s-%s-%s" % (self._api_secret, user.token, user.perms))
    return hash.hexdigest()

  def fft_cookie (self, user) :

    """A helper method to generate the 'fft' cookie string for a user."""
    
    fft = self.generate_fft(user)
    fft_cookie = "fft=%s" % fft
    return str(fft_cookie)

  def generate_password (self, length=58) :

    """A helper method to generate a new password."""
    
    return binascii.b2a_base64(os.urandom(length)).strip()

#
#
#

class FlickrUser (db.Model) :

  """FlickrUser is a simple data model for storing Flickr specific
  information about users. It has the following properties:

  * nsid - The user's Flickr NSID.
  
  * username - The user's Flickr screen name.

  * token - A Flickr API auth token for the user.

  * perms - The permissions that the Flickr API auth token
    was created with.

  * email - this is empty by default and left up to application's
    to handle; it just seemed like one of those things that might
    be handy.

  * created - A Google AppEngine DateTimeProperty representing
    when the (FlickrUser/App) record was created.
    
  * password - a 'password' for the user; used internally

  """
  
  password = db.StringProperty()
  token = db.StringProperty()
  perms = db.IntegerProperty()
  username = db.StringProperty()
  nsid = db.StringProperty()
  email = db.EmailProperty()
  created = db.DateTimeProperty(auto_now_add=True)  

  # maybe add a token-crumb to be extra pedantic about token requests?
