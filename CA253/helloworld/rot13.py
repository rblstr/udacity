import webapp2
import jinja2

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

urls = [
    ("/rot13", Rot13Handler)
]

app = webapp2.WSGIApplication(urls, debug=True)
