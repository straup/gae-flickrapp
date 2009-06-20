from google.appengine.ext import db

class dbFlickrUser (db.Model) :

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
  buddyicon_url = db.StringProperty()
  path_alias = db.StringProperty()
  created = db.DateTimeProperty(auto_now_add=True)  

class dbFlickrUserBlocked (db.Model) :

  blocker_nsid = db.StringProperty()
  blocked_nsid = db.StringProperty()
  date_blocked = db.DateTimeProperty(auto_now_add=True)

class dbFlickrUserMembership (db.Model) :

  nsid = db.StringProperty()
  opted_out = db.BooleanProperty()  
