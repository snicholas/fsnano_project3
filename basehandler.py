import os
import webapp2
import jinja2
import re
import hmac
import string
import random

from google.appengine.ext import db
from blogpost import BlogPost
from bloguser import BlogUser

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PSW_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

class Handler(webapp2.RequestHandler):
    def create_salt(self):
        return ''.join([random.choice(string.letters) for i in range(10) ])
    def hash_password(self,password, salt=None):
        if not salt:
            salt = self.create_salt()
        hashedpass = hmac.new(str(salt),password).hexdigest()
        return (hashedpass, salt)
    def user_exist(self, username):
        if username:
            user = db.GqlQuery("select * from BlogUser Where username = '%s'" % username).get()
            if user:
                return True
        return False
    def login(self,username, password):
        if username and password:
            user = db.GqlQuery("select * from BlogUser Where username = '%s'" % username).get()
            if user and self.hash_password(password, user.salt)[0] == user.hashedPassword:
                self.response.headers.add_header('Set-Cookie', 'user=%s|%s; Path=/' % (str(user.key().id()),str(user.hashedPassword)))
                return user
    def get_user_from_cookie(self):
        cookie=self.request.cookies.get('user')
        if cookie:
            uid,hp=cookie.split('|')
            user=BlogUser.get_by_id(int(uid))
            if user and hp==user.hashedPassword:
                return user
    def get_username_from_cookie(self):
        cookie=self.request.cookies.get('user')
        if cookie:
            uid,hp=cookie.split('|')
            user=BlogUser.get_by_id(int(uid))
            if user and hp==user.hashedPassword:
                return user.username
        return ""
    def valid_username(self,username):
        return USER_RE.match(username)
    def valid_password(self,pw):
        return PSW_RE.match(pw)
    def valid_email(self,email):
        return EMAIL_RE.match(email)

    def write (self, *a, **kw):
        self.response.write(*a,**kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template, **kw))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.user = self.get_user_from_cookie()
        if self.user:
            self.username_logged = self.user.username
