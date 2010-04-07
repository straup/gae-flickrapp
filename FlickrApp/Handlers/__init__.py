from FlickrApp import FlickrApp
import FlickrApp.User.Membership as Membership

from google.appengine.ext.webapp import template
import os.path
import copy

from FlickrApp.ext.Flickr import API as flickr

# If you're wondering this is mostly just a helper
# class to provide a bunch of utility methods

class FlickrAppRequest (FlickrApp) :

  def __init__ (self, config) :

    FlickrApp.__init__(self, config['flickr_apikey'], config['flickr_apisecret'])

    self.config = config
    self.min_perms = config['flickr_minperms']

    self.config_pub = copy.deepcopy(config)
    del(self.config_pub['flickr_apisecret'])

    self.membership = None
    self.template_values = {}

  def check_useragent(self, **kwargs):

    self.uastring = self.request.headers.get('user_agent')

    self.browser = {
      'iphone' : 0,
      'ipad' : 0,
      'mobile' : 0,
    }

    if "Mobile" in self.uastring and "Safari" in self.uastring:
        self.browser['iphone'] = 1
        self.browser['mobile'] = 1

    if "Mobile" in self.uastring and "iPad" in self.uastring:
        self.browser['iphone'] = 0
        self.browser['ipad'] = 1

    if self.config.get('debug_is_mobile', False):
      self.browser['iphone'] = 1
      self.browser['mobile'] = 1

    if kwargs.get('assign_template_vars', False):
      self.assign('user_agent', self.uastring)
      self.assign('browser', self.browser)

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

    self.check_useragent(assign_template_vars=True)

    #
    # but at least for now, it is and it does...
    #

    self.assign("config", self.config_pub)
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

  #
  # helper methods to get flickr specifics for a user - this is maybe
  # not the best place to put these -- some sort of generic Utils class
  # might be nicer -- but since they rely on proxied/auth API calls
  # that in turn rely on the API secret which is passed in to the object
  # constructor at run-time this is where they'll live for now...
  #

  def flickr_get_user_info (self, nsid) :

    # note that we use proxy_api_call which is already cached

    args = {
      'user_id' : nsid,
      }

    if self.user:
      args['auth_token'] = self.user.token

    rsp = self.proxy_api_call('flickr.people.getInfo', args)

    if not rsp or rsp['stat'] != 'ok' :
      return

    return rsp['person']

  def flickr_get_buddyicon (self, nsid) :

      user = self.flickr_get_user_info(nsid)

      if not user :
        return 'http://www.flickr.com/images/buddyicon.jpg'

      if int(user['iconserver']) == 0 :
        return 'http://www.flickr.com/images/buddyicon.jpg'

      return "http://farm%s.static.flickr.com/%s/buddyicons/%s.jpg" % (user['iconfarm'], user['iconserver'], nsid)

  def flickr_get_pathalias (self, nsid) :

      user = self.flickr_get_user_info(nsid)

      if not user :
        return None

      url = rsp['person']['photosurl']['_content']

      if url.endswith("/") :
        url = url[:-1]

      path_alias = os.path.basename(url)
      return path_alias
