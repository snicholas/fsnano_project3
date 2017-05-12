from google.appengine.ext import db

class BlogUser(db.Model):
    username = db.StringProperty( required = True )
    hashedPassword = db.StringProperty( required = True )
    salt = db.StringProperty( required = True )
    created = db.DateTimeProperty( auto_now_add = True )
