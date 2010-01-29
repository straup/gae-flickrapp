# THIS IS NOT READY FOR USE...

import APIApp
from FlickrApp.ext.Flickr import API as flickr

class FlickrAppAPI (APIApp.APIApp) :

    def __init__ (self) :

        APIApp.APIApp.__init__(self)        

        self.get_handlers = {}
        self.post_handlers = {}
        
    def get (self) :

        self.dispatch(self.get_handlers)
        return
    
    def post (self) :

        self.dispatch(self.post_handlers)
        return

    def set_handler (self, http_method, api_method, object_method) :

        if http_method == 'GET' :
            self.get_handlers[ api_method ] = object_method
        else :
            self.post_handlers[ api_method ] = object_method

    def ensure_crumb (self, path) :

        if not self.validate_crumb(self.user, path, self.request.get('crumb')) :
            self.api_error(400, 'Invalid crumb')
            return False

        return True

    def dispatch (self, handlers) :

        method = self.request.get('method')

        if not handlers.has_key(method) :
            self.api_error(999, 'Unknown method')
            return

        format = self.request.get('format')

        if format and not format in self.valid_formats :
            self.api_error(999, 'Not a valid format')
            return

        if format :
            self.format = format

        try :
            m = getattr(self, handlers[ method ])
            m()

        except Exception, e :
            self.api_error(999, 'Dispatch error: %s (that sometimes means there was a problem on the AppEngine side of things...)' % e)
            return

        return

    def echo (self) :

        self.api_ok()
        return

    def generate_signature (self) :

        required = ('crumb',)

        skip_list = ('crumb', 'format', 'method')

        if not self.ensure_args(required) :
            return

        if not self.ensure_crumb('method=signature') :
            return

        query = self.request.queryvars
        args = {}

        for key, value in query.items() :

            if key in skip_list :
                continue

            args[ key ] = value            

        sig = flickr.sign_args(self._api_secret, args)

        self.api_ok({'signature' : sig})
        return
