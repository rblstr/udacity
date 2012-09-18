import webapp2
import jinja2

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

class MainPage(BaseHandler):
    def get(self):
        self.write("Hello, World!")

urls = [
    ('/', MainPage)
]

app = webapp2.WSGIApplication(urls, debug=True)
