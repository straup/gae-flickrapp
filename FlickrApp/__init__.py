from google.appengine.ext import webapp
from google.appengine.api import memcache

from django.utils import simplejson
import User

import os
import binascii
import time
import datetime
import md5
import urllib
from urlparse import urlparse

import string
import random

import base64

from FlickrApp.ext import pyDes
from FlickrApp.ext.Flickr import API as flickr

import logging

try:
  # grrrrr.....
  # https://code.google.com/p/googleappengine/issues/detail?id=985#c20
  urllib.getproxies_macosx_sysconf = lambda: {}
except Exception, e:
  pass

#
#
#

class FlickrAppException (Exception) :
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return repr(self.value)

class FlickrAppAPIException (FlickrAppException) :
  def __init__(self, value):
    self.value = value

class FlickrAppCrumbException (FlickrAppException) :
  def __init__(self, value):
    self.value = value

class FlickrAppNewUserException (FlickrAppException) :
  def __init__(self, value=''):
    self.value = value

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

    self.crypto = None
    self.canhas_crypto()
    
  def canhas_crypto (self) :

    # A placeholder for some imaginary better day...
    # This isn't necessarily fast but then it doesn't
    # really need to be so let's just go with the
    # simple thing for now.
    
    self.crypto = 'pydes'
    return True
  
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

    user = User.get_user_by_password(whoami[1])

    if not user :
      return False

    self.user = user

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

  def do_flickr_auth (self, min_perms=None, redir=None) :

    """
    This method will generate and redirect the user to the Flickr
    API Auth endpoint where the user will be prompted to approve
    your request for a Flickr token (with 'min_perms' permissions).
    """

    args = {'api_key' : self._api_key}

    extra = []

    if redir :
      extra.append('redir=%s' % redir)
    else :
      extra.append('redir=%s' % urllib.quote(self.request.path))

    crumb = self.generate_crumb(None, 'flickrauth', 5)
    extra.append('crumb=%s' % urllib.quote(crumb))

    args['extra'] = "&".join(extra)

    if min_perms:
      args['perms'] = min_perms

    sig = flickr.sign_args(self._api_secret, args)

    args['api_sig'] = sig

    query = urllib.urlencode(args)

    url = "http://www.flickr.com/services/auth/?%s" % query

    self.redirect(url)

  def flickr_sign_args (self, args) :
    return flickr.sign_args(self._api_secret, args)

  def do_token_dance (self, **args) :

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

        try :

          new_users = True
          self.do_token_dance(allow_new_users=new_users)

        except FlickrApp.FlickrAppNewUserException, e :

          self.assign('error', 'no_new_users')

        except FlickrApp.FlickrAppAPIException, e :

          self.assign('error', 'api_error')

        except FlickrApp.FlickrAppException, e :

          self.assign('error', 'app_error')
          self.assign('error_message', e)      

        except Exception, e:

          self.assign('error', 'unknown')      
          self.assign('error_message', e)

        self.display("token_dance.html")        
        return

    """

    frob = self.request.get('frob')

    if not frob or frob == '' :
      raise FlickrAppException('Missing frob!')

    extra = self.request.get('extra')
    e_params = {}

    if extra and extra != '' :
    	extra = urlparse(extra)
        e_params = dict([part.split('=') for part in extra[2].split('&')])

    crumb = urllib.unquote(e_params['crumb'])

    if not self.validate_crumb(None, 'flickrauth', crumb) :
        raise FlickrAppCrumbException('Invalid crumb')

    api_args = {'frob': frob, 'check_response' : True}

    rsp = self.api_call('flickr.auth.getToken', api_args)

    if not rsp :
        raise FlickrAppAPIException('Failed to get token')

    token = rsp['auth']['token']['_content']
    name = rsp['auth']['user']['username']
    nsid = rsp['auth']['user']['nsid']
    perms = rsp['auth']['perms']['_content']
    user_perms = self.perms_map[perms]

    user = User.get_user_by_nsid(nsid)

    if not user :
    	if args.has_key('allow_new_users') and not args['allow_new_users'] :
            raise FlickrAppNewUserException()

    if not user :

    	args = {
        'password' : self.generate_password(),
        'token' : token,
        'username' : name,
        'nsid' : nsid,
        'perms' : user_perms,
        }

        user = User.create(args)

    else :

    	credentials = {
        'token' : token,
        'perms' : user_perms,
        'username' : name,
        }

        User.update_credentials(user, credentials)

    self.response.headers.add_header('Set-Cookie', self.ffo_cookie(user))
    self.response.headers.add_header('Set-Cookie', self.fft_cookie(user))

    if e_params.has_key('redir') :
    	self.redirect(urllib.unquote(e_params['redir']))
    else :
  	self.redirect("/")

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
    except Exception, e:

      logging.error("[flickrapp] Flickr API call %s failed: %s (%s)" % (method, e, type(e)))

      if not check_response :
        return { 'stat' : 'fail', 'message' : 'Flickr API call failed (AppEngine says "%s")' % e, 'code' : 999 }

      return None

    if check_response and json['stat'] != 'ok' :
      logging.warning("[flickrapp] Flickr API call %s did not return OK" % method)
      return None

    return json

  def proxy_api_call (self, method, args, ttl=0) :

    args['method'] = method
    sig = flickr.sign_args(self._api_secret, args)

    memkey = "%s_%s" % (method, sig)
    cache = memcache.get(memkey)

    if cache :
      return cache

    rsp = self.api_call(method, args)

    if not rsp :
      return None

    if rsp['stat'] == 'ok' :
      memcache.add(memkey, rsp, ttl)

    return rsp

  def check_token (self, min_perms) :

    """A helper method to ensure that the currently logged in user's
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

    if user :
      fft = "%s-%s-%s" % (self._api_secret, user.token, user.perms)
    else :
      fft = "%s-%s" % (self._api_secret, self.request.remote_addr)

    hash = md5.new()
    hash.update(fft)
    return hash.hexdigest()

  def fft_cookie (self, user) :

    """A helper method to generate the 'fft' cookie string for a user."""
    
    fft = self.generate_fft(user)
    fft_cookie = "fft=%s" % fft
    return str(fft_cookie)

  def generate_password (self, length=58) :

    """A helper method to generate a new user password."""
    
    return self.generate_secret(length)

  def generate_confirmation_code (self, length) :

    """A helper method to generate URL safe confirmation codes."""
    
    code = self.generate_secret(length)
    code = code.replace("/", self.generate_alpha())
    code = code.replace("+", self.generate_alpha())
    code = code.replace("=", self.generate_alpha())       
    return code

  def generate_alpha (self) :

    """A helper method to generate a random alpha character."""
    
    if int(time.time()) % 2 :
      return string.lowercase[random.randint(0, len(string.uppercase)-1)]
    
    return string.uppercase[random.randint(0, len(string.lowercase)-1)]    

  def generate_secret (self, length) :

    """A helper method to generate a new secret."""

    return binascii.b2a_base64(os.urandom(length)).strip()

  def crumb_secret (self, user) :

    """ tbd """

    if user :
      secret = "%s%s" % (self._api_secret, user.password)
    else :
      secret = "%s%s" % (self._api_secret, self.request.user_agent)

    hash = md5.new()
    hash.update(secret)
    hex = hash.hexdigest()

    return hex[:8]

  def generate_crumb (self, user, path, ttl=30) :

    """ tbd """

    # ttl is measured in minutes

    fft = self.generate_fft(user)
    secret = self.crumb_secret(user)

    now = datetime.datetime.fromtimestamp(time.time())
    delta = datetime.timedelta(minutes=ttl)
    then = now + delta
    expires = then.strftime("%s")

    crumb = "%s:%s:%s" % (fft, path, expires)

    enc = self.encrypt(crumb, secret)
    b64 = base64.b64encode(enc)

    return b64

  def validate_crumb(self, user, path, crumb_b64) :

    """ tbd """

    secret = self.crumb_secret(user)

    crumb_enc = base64.b64decode(crumb_b64)
    crumb_raw = self.decrypt(crumb_enc, secret)

    if not crumb_raw :
      return False

    try :
      (crumb_fft, crumb_path, crumb_expires) = crumb_raw.split(":")
    except Exception, e :
      return False

    if crumb_fft != self.generate_fft(user) :
      return False

    if crumb_path != path :
      return False

    if (int(crumb_expires) < int(time.time())) :
      return False

    return True

  def encrypt (self, raw, secret) :

    """ tbd """

    des = pyDes.des(secret)
    enc = des.encrypt(raw, "*")

    return enc

  def decrypt (self, enc, secret) :

    """ tbd """

    des = pyDes.des(secret)
    raw = des.decrypt(enc, "*")

    return raw
