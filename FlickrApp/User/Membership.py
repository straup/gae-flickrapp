from google.appengine.ext import db
from FlickrApp.Tables import dbFlickrUserMembership

def retrieve (nsid) :

    gql = "SELECT * FROM dbFlickrUserMembership WHERE nsid = :1"
    res = db.GqlQuery(gql, nsid)
    return res.get()

def has_user_opted_out (nsid) :
    
    user = retrieve(nsid)

    if not user :
        return False
    
    return user.opted_out
    
def create (nsid) :

    user = dbFlickrUserMembership()
    user.nsid = nsid
    user.opted_out = False
    user.put()
    
    return user
        
def opt_in (nsid) :

    user = retrieve(nsid)

    if user :
        user.opted_out = False
        user.put()
    
def opt_out (nsid) :

    user = retrieve(nsid)

    if user :
        user.opted_out = True
        user.put()
