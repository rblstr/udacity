import webapp2
import jinja2

import re
import random
import string
import hashlib

from google.appengine.ext import db

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

class Rot13Handler(BaseHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')
        self.render('rot13-form.html', text = rot13)

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r'^.{3,20}$')
def valid_password(password):
    return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return EMAIL_RE.match(email)

class UserSignupHandler(BaseHandler):
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
        
        if not success:
            self.render("user-form.html", **details)
        else:
            self.redirect('/welcome?username=%s' % username)

class WelcomeHandler(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if not valid_username(username):
            self.redirect('/signup')
        else:
            self.write('Welcome, %s!' % username)

class Art(db.Model):
    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class AsciiChanHandler(BaseHandler):
    def render_front(self, title="", art="", error=""):
        arts = db.GqlQuery("select * from Art order by created desc")
        self.render("front.html", title=title, art=art, error=error, arts=arts)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")

        if title and art:
            a = Art(title=title, art=art)
            a.put()
            self.redirect("/asciichan")
        else:
            error="you need to provide both title and art!"
            self.render_front(title=title, art=art, error=error)

class Blog(db.Model):
    subject = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    created = db.DateProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.blog.replace('\n', '<br>')
        return render_str("post.html", b = self)

class BlogFrontHandler(BaseHandler):
    def get(self, blog_id=""):
        if blog_id:
            blog = Blog.get_by_id(int(blog_id))
            if not blog:
                self.error('404')
                return
            blogs = [blog]
            self.render("blog-front.html", blogs=blogs)
        else:
            blogs = Blog.all().order('-created')
            self.render("blog-front.html", blogs=blogs)

    def post(self):
        return

class BlogNewPostHandler(BaseHandler):
    def render_front(self, subject="", blog="", error=""):
        self.render("blog-newblog.html", subject=subject, blog=blog, error=error)

    def get(self):
        self.render("blog-newblog.html")

    def post(self):
        subject = self.request.get('subject')
        blog = self.request.get('content')

        if subject and blog:
            blog = Blog(subject=subject, blog=blog)
            blog.put()
            self.redirect("/blog/%s" % str(blog.key().id()))
        else:
            error="subject and content please"
            self.render_front(subject=subject, blog=blog, error=error)

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
        if not validate_cookie or not user_id_cookie:
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
            user_id = '%s,%s' % (user_id_str, hashlib.md5(user_id_str).hexdigest())
            self.response.headers.add_header('Set-Cookie', "user_id=%s; Path=/" % user_id)
            self.redirect('/blog/welcome')
        else:
            self.render('login-form.html', **details)
        return

class BlogLogoutHandler(BaseHandler):
    def get(self):
        self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/" % "")
        self.redirect("/blog/signup")

urls = [
    ('/rot13', Rot13Handler),
    ('/signup', UserSignupHandler),
    ('/welcome', WelcomeHandler),
    ('/asciichan', AsciiChanHandler),
    ('/blog/?', BlogFrontHandler),
    ('/blog/([0-9]+)', BlogFrontHandler),
    ('/blog/newpost', BlogNewPostHandler),
    ('/blog/signup', BlogSignupHandler),
    ('/blog/welcome', BlogWelcomeHandler),
    ('/blog/login', BlogLoginHandler),
    ('/blog/logout', BlogLogoutHandler)
]

app = webapp2.WSGIApplication(urls, debug=True)
