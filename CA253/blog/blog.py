import webapp2
import jinja2

import re
import random
import string
import hashlib
import json
import logging
import datetime

from google.appengine.ext import db
from google.appengine.api import memcache

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader('templates'),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r'^.{3,20}$')
def valid_password(password):
    return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return EMAIL_RE.match(email)

class Blog(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", b = self)

class BlogHandlerBase(BaseHandler):

    def top_blogs(self, update=False):
        key = 'top'
        r = memcache.get(key)
        if r:
            query_time, blogs = r
        else:
            blogs = None
        if blogs is None or update:
            logging.error("DB QUERY")
            blogs = db.GqlQuery("select * "
                               "from Blog "
                               "order by created desc "
                               "limit 10")
            blogs = list(blogs)
            query_time = datetime.datetime.now()
            memcache.set(key, (query_time, blogs))
        return query_time, blogs 

    def get(self, blog_id=""):
        if blog_id:
            r = memcache.get(blog_id)
            if r:
                query_time, blog = r
            else:
                blog = None
            if blog is None:
                blog = Blog.get_by_id(int(blog_id))
                if not blog:
                    self.error('404')
                    return
                query_time = datetime.datetime.now()
                memcache.set(blog_id, (query_time, blog))
            blogs = [blog]
        else:
            query_time, blogs = self.top_blogs(update=False)#Blog.all().order('-created')
        queried_time = datetime.datetime.now() - query_time
        self.render_blogs(blogs, queried_time)

    def render_blogs(self, blogs):
        return

class BlogFrontHandler(BlogHandlerBase):
    def render_blogs(self, blogs, time):
        user_id_cookie = self.request.cookies.get('user_id')
        if not user_id_cookie or not validate_cookie(user_id_cookie):
            logged_in = False
            user_name = ""
        else:
            logged_in = True
            user_name = User.get_by_id(int(user_id_cookie.split("|")[0])).username
        time = time.seconds
        self.render("blog-front.html", blogs=blogs, login=logged_in, query_time=time, user_name=user_name)

class BlogFrontJSONHandler(BlogHandlerBase):
    def render_blogs(self, blogs):
        self.response.headers.add_header("Content-Type", "application/json")
        if blogs.count == 1:
            blog = {}
            blog["content"] = blogs[0].content
            blog["subject"] = blogs[0].subject
            blog["created"] = blogs[0].created.strftime("%a %B %d %H:%M:%S %Y")
            blog["last_modified"] = blogs[0].last_modified.strftime("%a %B %d %H:%M:%S %Y")
            self.write(json.dumps(blog))
        else:
            blog_objs = []
            for blog in blogs:
                blog_obj = {}
                blog_obj["content"] = blog.content
                blog_obj["subject"] = blog.subject
                blog_obj["created"] = blog.created.strftime("%a %B %d %H:%M:%S %Y")
                blog_obj["last_modified"] = blog.last_modified.strftime("%a %B %d %H:%M:%S %Y")
                blog_objs.append(blog_obj)
            self.write(json.dumps(blog_objs))

class BlogNewPostHandler(BlogHandlerBase):
    def render_front(self, subject="", content="", error=""):
        user_id_cookie = self.request.cookies.get('user_id')
        logged_in = False
        if not user_id_cookie or not validate_cookie(user_id_cookie):
            logged_in = False
        else:
            logged_in = True
        self.render("blog-newblog.html", subject=subject, blog=content, error=error, login=logged_in)

    def get(self):
        user_id_cookie = self.request.cookies.get('user_id')
        logged_in = False
        if not user_id_cookie or not validate_cookie(user_id_cookie):
            logged_in = False
        else:
            logged_in = True
        self.render("blog-newblog.html", login=logged_in)

    def post(self):
        user_id_cookie = self.request.cookies.get('user_id')
        if not user_id_cookie or not validate_cookie(user_id_cookie):
            self.redirect("/blog")
            return

        user = User.get_by_id(int(user_id_cookie.split("|")[0]))

        subject = self.request.get('subject') 
        content = self.request.get('content')

        if subject and content:
            blog = Blog(subject=subject, content=content, author=user.username)
            blog.put()
            self.top_blogs(update=True)
            self.redirect("/blog/%s" % str(blog.key().id()))
        else:
            error="subject and content please"
            self.render_front(subject=subject, content=content, error=error)

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)

def make_salt():
    return ''.join(random.choice(string.letters) for i in range(5))

def hash_password(username, password, salt=None):
    if not salt:
        salt = make_salt()
    hashed = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (hashed, salt)

def validate_password(username, password, h):
    hashed = h.partition('|')[0]
    salt = h.partition('|')[2]
    return hashlib.sha256(username + password + salt).hexdigest() == hashed

class BlogSignupHandler(BaseHandler):
    def get(self):
        self.render('user-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        password2 = self.request.get('verify')
        email = self.request.get('email')

        details = dict(username=username, email=email) 
        success = True

        if not valid_username(username):
            details["username_error"] = "That's not a valid username."
            success = False
        if not valid_password(password):
            details["password_error"] = "That's not a valid password."
            success = False
        elif not valid_password(password2) or password != password2:
            details["verification_error"] = "Your passwords didn't match"
            success = False
        if email and not valid_email(email):
            details["email_error"] = "That's not a valid email address"
            success = False
        
        if User.all().filter("username =", username).get():
            details["username_error"] = "Username already in use"
            success = False

        if not success:
            self.render("user-form.html", **details)
        else:
            hashed_password = hash_password(username, password)

            user = User(username=username, password=hashed_password)
            user.put()

            user_id_str = str(user.key().id())
            
            user_id = "%s|%s" % (user_id_str, hashlib.md5(user_id_str).hexdigest())

            self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/" % user_id)
            self.redirect('/blog/welcome')

def validate_cookie(cookie):
    key = cookie.partition("|")[0]
    hashed = cookie.partition("|")[2]
    return hashlib.md5(key).hexdigest() == hashed

class BlogWelcomeHandler(BaseHandler):
    def get(self):
        user_id_cookie = self.request.cookies.get('user_id')
        if not user_id_cookie or not validate_cookie(user_id_cookie):
            logging.error("No login user id cookie")
            self.redirect('/blog/signup')
        else:
            user_id = user_id_cookie.partition("|")[0]
            user = User.get_by_id(int(user_id))
            if user:
                self.write('Welcome, %s!' % user.username)
            else:
                self.redirect('/blog/signup')

class BlogLoginHandler(BaseHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        success = True 
        username = self.request.get('username')
        password = self.request.get('password')
        details = dict(username=username)

        if not valid_username(username):
            success = False
            details["error"] = "invalid username"
        else:
            user = User.all().filter('username =', username).get()
            if not user:
                success = False
                details["error"] = "no user by that username"
            else:
                if not validate_password(username, password, user.password):
                    success = False
                    details["error"] = "invalid password"

        if success:
            user_id_str = str(user.key().id())
            user_id = '%s|%s' % (user_id_str, hashlib.md5(user_id_str).hexdigest())
            self.response.headers.add_header('Set-Cookie', "user_id=%s; Path=/" % user_id)
            self.redirect('/blog/welcome')
        else:
            self.render('login-form.html', **details)
        return

class BlogLogoutHandler(BaseHandler):
    def get(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")
        self.redirect("/blog")

class BlogFlushHandler(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/blog")

urls = [
    ('/blog/?', BlogFrontHandler),
    ('/blog/.json', BlogFrontJSONHandler), #(?:\.json)
    ('/blog/([0-9]+)', BlogFrontHandler),
    ('/blog/([0-9]+).json', BlogFrontJSONHandler),
    ('/blog/newpost', BlogNewPostHandler),
    ('/blog/signup', BlogSignupHandler),
    ('/blog/welcome', BlogWelcomeHandler),
    ('/blog/login', BlogLoginHandler),
    ('/blog/logout', BlogLogoutHandler),
    ('/blog/flush', BlogFlushHandler),
]

app = webapp2.WSGIApplication(urls, debug=True)
