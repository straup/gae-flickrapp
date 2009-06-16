from google.appengine.ext import db
from FlickrApp.Tables import dbFlickrUser

def get_user_by_password (password) :

    users = db.GqlQuery("SELECT * FROM dbFlickrUser WHERE password = :1", password)
    return users.get()

def get_user_by_username (username) :

    users = db.GqlQuery("SELECT * FROM dbFlickrUser WHERE username = :1", username)
    return users.get()
    
def get_user_by_nsid (nsid) :
    
    users = db.GqlQuery("SELECT * FROM dbFlickrUser WHERE nsid = :1", nsid)
    return users.get()

def create (args) :

    user = dbFlickrUser()
    user.password = args['password']
    user.token = args['token']
    user.username = args['username']
    user.nsid = args['nsid']
    user.perms = args['perms']
    user.put()
    
    return user

# Please, write a proper 'update' method...

def set_buddyicon_url (user, url) :
    user.buddyicon_url = url
    user.put()
    
def update_credentials (user, creds) :

    user.token = creds['token']
    user.perms = creds['perms']
    user.username = creds['username']
    user.put()

