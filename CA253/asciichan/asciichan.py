import webapp2
import jinja2
import logging

from google.appengine.ext import memcache
from google.appengine.ext import db

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader('templates'),
                                autoescape = True)

class BaseHandler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))

class Art(db.Model):
    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class AsciiChanHandler(BaseHandler):
    def top_arts(self, update=True):
        key = 'top'
        if not update and key in CACHE:
            arts = CACHE[key]
        else:
            logging.error("DB QUERY")
            arts = db.GqlQuery("select * "
                               "from Art "
                               "order by created desc "
                               "limit 10")
            arts = list(arts)
            CACHE[key] = arts
        return arts

    def render_front(self, title="", art="", error=""):
        arts = self.top_arts()

        self.render("front.html", title=title, art=art, error=error, arts=arts)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")

        if title and art:
            a = Art(title=title, art=art)
            a.put()
            self.top_arts(True)
            self.redirect("/")
        else:
            error="you need to provide both title and art!"
            self.render_front(title=title, art=art, error=error)

urls = [
    ('/', AsciiChanHandler)
]

app = webapp2.WSGIApplication(urls, debug=True)
