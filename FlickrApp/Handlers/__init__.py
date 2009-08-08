from FlickrApp import FlickrApp
import FlickrApp.User.Membership as Membership

from google.appengine.api import memcache
from google.appengine.ext.webapp import template
import os.path

# If you're wondering this is mostly just a helper
# class to provide a bunch of utility methods

class FlickrAppRequest (FlickrApp) :

  def __init__ (self, config) :


    FlickrApp.__init__(self, config['flickr_apikey'], config['flickr_apisecret'])

    self.config = config
    self.min_perms = config['flickr_minperms']

    self.membership = None
    self.template_values = {}

  def check_logged_in (self, min_perms=None) :

    if not FlickrApp.check_logged_in(self, min_perms) :
      return False

    membership = Membership.retrieve(self.user.nsid)

    if not membership :
      membership = Membership.create(self.user.nsid)
      
    self.membership = membership
    self.has_opted_out = membership.opted_out

    return True
      
  def assign (self, key, value) :
    self.template_values[key] = value
    
  def display (self, template_name) :

    #
    # this should not live here. it is
    # also incomplete...
    #
    
    uastring = self.request.headers.get('user_agent')

    browser = {
    'iphone' : False,
    'mobile' : False,
    }
        
    if "Mobile" in uastring and "Safari" in uastring:
        browser['iphone'] = True
        browser['mobile'] = True            

    # browser['iphone'] = True
    # browser['mobile'] = True            

    self.assign('user_agent', uastring)
    self.assign('browser', browser)
    
    #
    # but at least for now, it is and it does...
    #
    
    self.assign("config", self.config)
    self.assign("host", self.request.host)
    self.assign("host_url", self.request.host_url)    
    self.assign("path_info", self.request.path_info)

    if self.user :
      self.assign('user', self.user)
      self.assign('logout_crumb', self.generate_crumb(self.user, "logout"))

    # this assumes that /templates lives in the same
    # directory as the FlickrApp package itself
    
    root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    path = os.path.join(root, 'templates', template_name)
    
    self.response.out.write(template.render(path, self.template_values))
