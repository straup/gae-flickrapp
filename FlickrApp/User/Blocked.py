from google.appengine.ext import db
from FlickrApp.Tables import dbFlickrUserBlocked

def is_user_blocked (blocked_nsid, blocker_nsid=None):

    query_args = [ blocked_nsid ]
    
    gql = "SELECT * FROM dbFlickrUserBlocked WHERE blocked_nsid = :1"

    if blocker_nsid :
      gql += " AND blocker_nsid = :2"
      query_args.append( blocker_nsid)
      
    blocks = db.GqlQuery(gql, *query_args)

    if blocks.count() == 0 :
      return False

    return True
  
def block_user (blocked_nsid, blocker_nsid, double_check=True) :

    if double_check :
        if is_user_blocked(blocked_nsid, blocker_nsid) :
            return True
    
    block = dbFlickrUserBlocked()
    block.blocked_nsid = blocked_nsid
    block.blocker_nsid = blocker_nsid
    block.put()

    return True

def unblock_user (blocked_nsid, blocker_nsid) :

    gql = "SELECT * FROM dbFlickrUserBlocked WHERE blocked_nsid = :1 AND blocker_nsid = :2"

    blocks = db.GqlQuery(gql, blocked_nsid, blocker_nsid)    
    db.delete(blocks)
    
    return True

def blocked_by_user (blocker_nsid) :

    gql = "SELECT * FROM dbFlickrUserBlocked WHERE blocker_nsid = :1"
    return db.GqlQuery(gql, blocker_nsid)
