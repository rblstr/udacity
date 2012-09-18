import webapp2
import jinja2

import re

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

urls = [
    ("/signup", UserSignupHandler),
    ("/welcome", WelcomeHandler)
]

app = webapp2.WSGIApplication(urls, debug=True)
