# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# aggiungere userid a BlogPost
# aggiungere calsse per like con userid, postid
# aggiungere controllo caneddit per modifica e cancellazione post solo propri
# aggiungere controllo can like autenticato e non ha gia messo like
# ripulire codice e conformarlo alle python style guide
# uniformare stile pagine login/logout a stile blog
# includere bootstrap
# dividere il codice in piu file e refactor generale
# commentare le funzioni e mettere __doc__
#aggiungere file README.md

import os
import webapp2
import jinja2
import re
import hmac
import string
import random

from basehandler import Handler
from blogpost import BlogPost
from bloguser import BlogUser

from google.appengine.ext import db

class MainPage(Handler):
    def render_front(self, template="front.html", blogs=None):
        self.render(template, blogs = blogs, username = self.username)

    def get(self):
        blogs = db.GqlQuery("select * from BlogPost order by created desc")
        self.render_front("index.html", blogs=blogs)

class BlogEntry(Handler):
    def get(self, postId):
        if postId:
            blog = BlogPost.get_by_id (int(postId))
            self.render("post.html", blog=blog)
        else:
            self.redirect("/")

class NewPost(Handler):
    def render_form(self, subject="",content="",error=""):
        self.render("newpost.html",subject=subject,content=content,error=error)
    def get(self):
        if self.user:
            self.render_form()
        else:
            self.redirect("/login")
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            bp = BlogPost(subject=subject, content=content, userid=self.user)
            bp.put()
            self.redirect("/%s" % bp.key().id())
        else:
            self.render("newpost.html",subject=subject,content=content,error="subject and content are mandatory!")

class Welcome(Handler):
    def get(self):
        if self.user:
            blogs = BlogPost.all().filter('userid =', self.user)
            self.render("welcome.html", username=self.user.username, blogs=blogs)
        else:
            self.redirect("/signup")
class Logout(Handler):
    def get(self):
        username = self.get_username_from_cookie()
        if username:
            self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        self.redirect("/signup")
class Login(Handler):
    def render_form(self, username="", error=""):
        self.render("login.html", username=username, error=error)
    def get(self):
        username = self.get_username_from_cookie()
        if username:
            cookie=self.request.cookies.get('user')
            password=cookie.split('|')[1]
            if self.login(username,password):
                self.redirect("/welcome")
            else:
                self.render_form(username=username, error="Invalid login")
        else:
            self.render_form(username=username)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        if username and password:
            if self.login(username,password):
                self.redirect("/welcome")
        self.render_form(username=username, error="Invalid login")
class SignUp(Handler):
    def create_user(self,username="", password=""):
        if username and password:
            hashed=self.hash_password(password)
            user = BlogUser(username=username, hashedPassword=hashed[0], salt=hashed[1])
            user.put()
            return user

    def render_form(self, username="",email="",uname_error="",password_error="",verify_error="", email_error=""):
        self.render("signup.html",username = username,email = email,uname_error = uname_error,password_error = password_error,verify_error = verify_error, email_error = email_error)
    def get(self):
        self.render_form()
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        uname_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        if not self.valid_username(username):
            uname_error = "Invalid username"
        if not self.valid_password(password):
            password_error = "Invalid password"
        if password != verify:
            verify_error = "Password don't match verify"
        if email and not self.valid_email(email):
            email_error = "Invalid email"
        if uname_error or password_error or verify_error or email_error:
            self.render_form(username,email,uname_error,password_error,verify_error, email_error)
        else:
            if not self.user_exist(username):
                user = self.create_user(username,password)
                if user:
                    self.response.headers.add_header('Set-Cookie', 'user=%s|%s; Path=/' % (user.key().id(),user.hashedPassword))
                    self.redirect("/welcome")
                else:
                    uname_error = 'Something went wrong!'
                    self.render_form(username,email,uname_error,password_error,verify_error, email_error)
            else:
                uname_error = 'User already exist'
                self.render_form(username,email,uname_error,password_error,verify_error, email_error)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/(\d+)', BlogEntry),
    ('/newpost', NewPost),
    ('/signup', SignUp),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome)
], debug=True)
