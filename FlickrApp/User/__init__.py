from google.appengine.ext import db
from FlickrApp.Tables import dbFlickrUser

def get_all_users() :

    # FIX ME: proper counts/ pagination
    rsp = db.GqlQuery("SELECT * FROM dbFlickrUser")
    users = rsp.fetch(rsp.count())

    return users
    
def get_user_by_password (password) :

    users = db.GqlQuery("SELECT * FROM dbFlickrUser WHERE password = :1", password)
    return users.get()

def get_user_by_username (username) :

    users = db.GqlQuery("SELECT * FROM dbFlickrUser WHERE username = :1", username.strip())
    return users.get()
    
def get_user_by_nsid (nsid) :
    
    users = db.GqlQuery("SELECT * FROM dbFlickrUser WHERE nsid = :1", nsid.strip())
    return users.get()

def create (args) :

    user = dbFlickrUser()
    user.password = args['password'].strip()
    user.token = args['token'].strip()
    user.username = args['username'].strip()
    user.nsid = args['nsid'].strip()
    user.perms = args['perms']

    # A combination of empty strings being created as <null>
    # values and still being uncertain what the best way to
    # test things is in django template land...
    
    user.buddyicon_url = ''
    user.path_alias = ''
    
    user.put()
    
    return user

# Please, write a proper 'update' method...

def set_buddyicon_url (user, url) :
    user.buddyicon_url = url
    user.put()

def set_path_alias (user, path_alias) :
    user.path_alias = path_alias
    user.put()
    
def update_credentials (user, creds) :

    user.token = creds['token']
    user.perms = creds['perms']
    user.username = creds['username']
    user.put()

