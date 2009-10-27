# http://github.com/straup/gae-flickrapp/tree/master

from FlickrApp import FlickrApp

# config is nothing more than a hash (or a 'dict') containing keys
# specific your application. It needs to live in your application's
# root folder (the one containing main.py and friends)

from config import config

# This is your application's base class. It handles the
# sub-classing of FlickrApp itself and takes care of
# managing basic config information like your API key
# and Flickr permissions. It must contain the following
# keys:
#
# flickr_apikey (your Flickr API key)
# flickr_apisecret (your Flickr API key's application/signing secret)
# flickr_minperms (read, write, delete)

class HelloWorldApp (FlickrApp) :

    def __init__ (self) :
        
        FlickrApp.__init__(self, config['flickr_apikey'], config['flickr_apisecret'])
        
        self.config = config
        self.min_perms = config['flickr_minperms']

# This is your application's "splash" page. In this example
# it does nothing more than let you sign in and sign out using
# a Flickr account. Note the call to "generate_crumb". The
# corresponding "validate_crumb" method is called by the
# signout handler.

class MainApp(HelloWorldApp) :

    def get (self) :

        if not self.check_logged_in(self.min_perms) :
            self.response.out.write("<a href=\"/signin\">Click here to sign in using Flickr</a>")
            return

        crumb = self.generate_crumb(self.user, 'logout')
                    
        self.response.out.write("You are logged in with your %s Flickr account<br /><br />" % self.user.username)
        
        self.response.out.write("<form method=\"POST\" action=\"signout\">")
        self.response.out.write("<input type=\"hidden\" name=\"crumb\" value=\"%s\" />" % crumb)
        self.response.out.write("<input type=\"submit\" value=\"SIGN OUT\" />")
        self.response.out.write("</form>")
        return

# In Flickr-speak this is the "callback" URL that the user
# is redirected to once they have authed your application.

class TokenDance (HelloWorldApp) :

    def get (self):

        try :

            new_users = True
            self.do_token_dance(allow_new_users=new_users)
            
        except FlickrApp.FlickrAppNewUserException, e :
            self.response.out.write('New user signups are currently disabled.')

        except FlickrApp.FlickrAppAPIException, e :
            self.response.out.write('The Flickr API is being cranky.')

        except FlickrApp.FlickrAppException, e :
            self.response.out.write('Application error: %s' % e)
      
        except Exception, e:
            self.response.out.write('Unknown error: %s' % e)

        return
    
# This is where you send a user to sign in. If they are not
# already authed then the application will take care generating
# Flickr Auth frobs and other details.

class Signin (HelloWorldApp) :
    
    def get (self) :
        if self.check_logged_in(self.min_perms) :
            self.redirect("/")
            
        self.do_flickr_auth(self.min_perms, '/')
        return

# This is where you send a user to log them out of your
# application. The user may or may not still be logged in to
# Flickr. Note how we're explictly zero-ing out the cookies;
# that should probably be wrapped up in a helper method...

class Signout (HelloWorldApp) :

    def post (self) :

        if not self.check_logged_in(self.min_perms) :
            self.redirect("/")

        crumb = self.request.get('crumb')

        if not crumb :
            self.redirect("/")
            
        if not self.validate_crumb(self.user, "logout", crumb) :
            self.redirect("/")

        self.response.headers.add_header('Set-Cookie', 'ffo=')
        self.response.headers.add_header('Set-Cookie', 'fft=')    
        
        self.redirect("/")
    
