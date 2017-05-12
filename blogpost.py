from google.appengine.ext import db
from bloguser import BlogUser

class BlogPost(db.Model):
    subject = db.StringProperty( required = True )
    content = db.TextProperty( required = True )
    created = db.DateTimeProperty( auto_now_add = True )
    userid =  db.ReferenceProperty(BlogUser)
