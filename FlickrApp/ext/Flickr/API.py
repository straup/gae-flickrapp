"""Flickr API Acesss

General Doc: http://www.flickr.com/services/api/
Authentication Doc:  http://www.flickr.com/services/api/auth.spec.html

Sample usage:
	import Flickr.API

	# flickr.test.echo:
	api = Flickr.API.API(key, secret)
	test_rsp = api.execute_method(method='flickr.test.echo', sign=False)
	if test_rsp.code == 200:
		print test_rsp.read()

	# flickr.auth.getFrob:
	frob_request = Flickr.API.Request(method='flickr.auth.getFrob')
	frob_rsp = api.execute_request(frob_request)
	if frob_rsp.code == 200:
		frob_rsp_et = xml.etree.ElementTree.parse(frob_rsp)
		if frob_rsp_et.getroot().get('stat') == 'ok':
			frob = frob_rsp_et.findtext('frob')
	
	# get the desktop authentication url
	auth_url = api.get_authurl('write', frob=frob)

	# ask the user to authorize your app now using that url
	print "auth me:  %s" % (auth_url,)
	input = raw_input("done [y]: ")
	if input.lower() not in ('', 'y', 'yes'):
		sys.exit()

	# flickr.auth.getToken:
	token_rsp = api.execute_request(Flickr.API.Request(method='flickr.auth.getToken', frob=frob, format='json', nojsoncallback=1))
	if token_rsp.code == 200:
		token_rsp_json = simplejson.load(token_rsp)
		if token_rsp_json['stat'] == 'ok':
			token = str(token_rsp_json['auth']['token']['_content'])

	# flickr.activity.userPhotos (requires authentication):
	activity_rsp = api.execute_request(Flickr.API.Request(method='flickr.activity.userPhotos', auth_token=token, timeframe='1d', format='rest'))
	if activity_rsp.code == 200:
		activity_rsp_et = xml.etree.ElementTree.parse(activity_rsp)
		if activity_rsp_et.getroot().get('stat') == 'ok':
			# do something with the activity
			xml.etree.ElementTree.dump(activity_rsp_et)

	# upload
	photo = open('photo.jpg', 'rb')
	upload_request = Flickr.API.Request("http://api.flickr.com/services/upload", auth_token=token, title='test upload', photo=photo)
	upload_response = api.execute_request(upload_request, sign=True, encode=Flickr.API.encode_multipart_formdata)

	# or upload this way
	upload_response = api.execute_upload(filename='photo.jpg', args={'auth_token':token, 'title':'test upload', 'photo':photo})
"""

__author__ = "Gilad Raphaelli"
__version__ = "0.4.3"

try:
	import hashlib
except ImportError:
	import md5 as hashlib

import mimetypes,urllib,urllib2
import warnings
import API

import google.appengine.api.urlfetch as urlfetch
import StringIO


def encode_multipart_formdata(args):
	""" Encode upload as multipart/form-data. From http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/146306 """
	BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
	CRLF = '\r\n'
	L = []
	for (key, value) in args.items():
		if hasattr(value, 'read'):
			if hasattr(value, 'name'):
				filename = value.name
			elif args.has_key('title'):
				filename = args['title']
			else:
				filename = 'unknown'
			L.append('--' + BOUNDARY)
			L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
			L.append('Content-Type: %s' % get_content_type(filename))
			L.append('')
			L.append(value.read())
		else:
			L.append('--' + BOUNDARY)
			L.append('Content-Disposition: form-data; name="%s"' % key)
			L.append('')
			L.append(value)
	L.append('--' + BOUNDARY + '--')
	L.append('')
	body = CRLF.join(L)
	headers = {
		'Content-Type': 'multipart/form-data; boundary=%s' % BOUNDARY,
		'Content-Length': len(body)
	}
	return (headers, body)

def encode_urlencode(args):
	return ({},urllib.urlencode(args))

def get_content_type(filename):
	return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def sign_args(secret, args):
	""" Given a Flickr API secret and an array of args including an api_key key return an api_sig (string) """
	sig = secret
	for key in sorted(args.keys()):
		sig += key
		if args[key] is not None:
			sig += str(args[key])

	return hashlib.md5(sig).hexdigest()
	
class APIError(Exception): pass
class APIWarning(RuntimeWarning): pass

class API:
	""" To access the Flickr API """
	def __init__(self, key, secret=None):
		self.key = key
		self.secret = secret

	def execute_method(self, method, args={}, sign=True):
		""" Given a Flickr API method and arguments, construct a Flickr.API.Request and return a urllib2.addinfourl """
		args['method'] = method
		return self.execute_request(Request(**args), sign)

	def execute_upload(self, filename, args={}):
		try:
			photo = open(filename, mode='rb')
			args['photo'] = photo
		except IOError, (e.no, e.msg):
			raise APIError, "Unable to open %s - %s: %s" % (filename, e.no, e.msg)
			
		return self.execute_request(Request('http://api.flickr.com/services/upload/',**args), sign=True, encode=encode_multipart_formdata)

	def execute_request(self, request, sign=True, encode=encode_urlencode):
		""" Given a Flickr.API.Request return a Flickr.API.Response, altering
		the original Request.  The request will silently not sign if no secret
		is available. """
		
		request.args['api_key'] = self.key

		if sign and self.secret is not None:
			# Sign args as they are now, except photo
			args_to_sign = {}
			for (k,v) in request.args.items():
				if k not in ('photo'):
					args_to_sign[k] = v
				
			request.args['api_sig'] = self._sign_args(args_to_sign)

		request.add_header('Host', request.get_host())

		(headers, body) = encode(request.args)
		for (header, value) in headers.items():
			request.add_header(header, value)

		# urllib2 method goes POST when data is added (but make sure)
		request.add_data(body)
		if (request.get_method() != "POST"):
			raise Exception, "not a POST? Something is wrong here"
		
		response = urlfetch.fetch(request.get_full_url(), payload=body, method="POST", headers=headers, deadline=10)
		content = StringIO.StringIO(response.content)
		content.code = response.status_code
		return content

	def get_authurl(self, perms, **kwargs):
		""" Get a client authentication url for web-based and non-web based clients
		
		New in 0.4.1, use this method instead of get_auth_url """

		args = {
			'perms': perms,
			'api_key': self.key,
		}

		kwargs.update(args)

		kwargs['api_sig'] = sign_args(self.secret, kwargs)

		return "http://flickr.com/services/auth/?%s" % (urllib.urlencode(kwargs),)
		
	def get_auth_url(self, frob, perms):
		""" Given a frob obtained via a 'flickr.auth.getFrob' and perms
		(currently read, write, or delete) return a url for desktop client api
		authentication

		Deprecated in 0.4.1, use get_authurl for new applications """

		return get_authurl(perms, frob=frob)

	def _sign_args(self, args):
		return sign_args(self.secret, args)

class Request(urllib2.Request):
	""" A request to the Flickr API subclassed from urllib2.Request allowing for custom proxy, cache, headers, etc """
	def __init__(self, apiurl='http://api.flickr.com/services/rest/', **args):
		urllib2.Request.__init__(self, url=apiurl)
		self.args = args

if (__name__ == '__main__'):
	import sys
	try:
		key = sys.argv[1]
		secret = sys.argv[2]
	except IndexError:
		print "Usage: %s <key> <secret>" % (sys.argv[0],)
		sys.exit(1)

	api = API(key, secret)
	res = api.execute_method(method='flickr.test.echo', args={'foo':'bar'})
