from os import urandom
import uuid
import pickle
from flask import Flask, render_template, redirect, request, url_for, abort
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField
from wtforms.validators import ValidationError
from redis import StrictRedis
from rq import Queue
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network
from werkzeug.contrib.fixers import ProxyFix
from socket import gethostbyname
import requests
import hmac

allowed_sources = {
  "git.ligo.org": "gitlab",
  "github.com": "github",
  "hub.docker.com": "dockerhub"
}

class WebhookRegistrationForm(FlaskForm):
    def validate_url(form, field):
        url = urlparse(field.data)
        if url.scheme not in ['http','https']:
            raise ValidationError("This is not an http/https webhook!")

    def validate_webhook_source(form, field):
        url = urlparse(field.data)
        if url.hostname not in allowed_sources.keys():
            raise ValidationError("This is not a webhook from GitHub/DockerHub/LIGO GitLab!")

    src = StringField('Source', validators=[validate_url, validate_webhook_source])
    dst = StringField('Destination', validators=[validate_url])

class WebhookLockForm(FlaskForm):
    lock = BooleanField(u'Lock Webhook!')

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, num_proxies=2)

# we don't care about losing sessions
app.secret_key = urandom(50)

@app.route('/', methods=['GET', 'POST'])
def register():
    form = WebhookRegistrationForm()
    if form.validate_on_submit():
        r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
        src = form.data['src']
        dst = form.data['dst']
        secrets_key = src.rstrip('/')
        destinations_key  = secrets_key + ":destinations"

        # because the form has been validated we know it's from a known source

        if not r.exists(src):
            relaypoint = uuid.uuid4().hex
            r.set(src, relaypoint)
            r.set(relaypoint + ":token", uuid.uuid4().hex)
            r.set(relaypoint + ":source", src)
            r.set(relaypoint + ":locked", "False")
            webhook_type = allowed_sources.get(urlparse(src).hostname)
            r.set(relaypoint + ":uri", "https://webhooks.ligo.uwm.edu/%s/%s" % (webhook_type,relaypoint))

        relaypoint = r.get(src)
        if r.get(relaypoint + ":locked") == "False":
            r.sadd(relaypoint + ":destinations", dst.rstrip('/'))
        return redirect(url_for("relaypoint_info", relaypoint=relaypoint))
    else:
        return render_template('register.html', form=form)

@app.route('/info/<string:relaypoint>')
def relaypoint_info(relaypoint):
    r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
    src = r.get(relaypoint + ":source")
    if src is None:
        return abort(404)

    return render_template('info.html',
        src=r.get(relaypoint + ":source"),
        token=r.get(relaypoint + ":token"),
        destinations=r.smembers(relaypoint + ":destinations"),
        relaypoint_uri=r.get(relaypoint + ":uri"),
        relaypoint=relaypoint,
        locked=r.get(relaypoint + ":locked"))

@app.route('/lock/<string:relaypoint>', methods=['GET', 'POST'])
def relaypoint_lock(relaypoint):
    form = WebhookLockForm()

    r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
    src = r.get(relaypoint + ":source")
    if src is None:
        return abort(404)

    if form.validate_on_submit():
        if form.lock.data:
            r.set(relaypoint + ":locked", "True")
        return redirect(url_for("relaypoint_info", relaypoint=relaypoint))
    else:
        return render_template('lock.html', relaypoint=relaypoint, form=form)


@app.route('/gitlab/<string:relaypoint>', methods=['POST'])
def gitlab_webhook(relaypoint):
    if request.method == 'POST':
        if gethostbyname("git.ligo.org") != request.remote_addr:
            abort(403)

        try:
            hooktoken = request.headers.get('X-Gitlab-Token')
            payload = request.get_json()
        except:
            return abort(400)

        payload_src = payload['project']['web_url']
        r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
        src = r.get(relaypoint + ":source")
        destinations = r.smembers(relaypoint + ":destinations")
        token = r.get(relaypoint + ":token")

        if (src is None or src != payload_src or
            not hmac.compare_digest(hooktoken,token)):
            return abort(403)

        q = Queue(connection=StrictRedis(host='redis', port=6379, db=1))
        q.enqueue('relay.posthook', payload, destinations)
        return "Thanks for the work, GitLab!"
    else:
        abort(404)

@app.route('/github/<string:relaypoint>', methods=['POST'])
def github_webhook(relaypoint):
    if request.method == 'POST':
        ip = request.remote_addr
        src_ip = ip_address(u'{}'.format(ip))
        whitelist = requests.get('https://api.github.com/meta').json()['hooks']

        # this is a for-else loop (look it up!)
        for valid_ip_range in whitelist:
            if src_ip in ip_network(valid_ip_range):
                break
        else:
            abort(403)

        try:
            # this will be set to None if no header
            alg, signature = request.headers.get('X-Hub-Signature').split('=')
            body = request.get_data()
            payload = request.get_json()
        except:
            return abort(400)

        payload_src = payload['repository']['html_url']
        r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
        src = r.get(relaypoint + ":source")
        destinations = r.smembers(relaypoint + ":destinations")
        token = r.get(relaypoint + ":token")

        if (src is None or src != payload_src or
            not validate_signature(body, secret=token.encode(), signature=signature)):
            return abort(403)

        q = Queue(connection=StrictRedis(host='redis', port=6379, db=1))
        q.enqueue('relay.posthook', payload, destinations)
        return "Thanks for the work, GitHub!"
    else:
        abort(404)

def validate_signature(body, secret=None, signature=None):
     # if unsigned, no need to validate
     if signature is None:
         return True

     # if signed, we cannot verify if not provided a secret
     if secret is None:
         return False

     # perform timing-attach-resilient comparison
     mac = hmac.new(secret, msg=body, digestmod='sha1')
     return hmac.compare_digest(mac.hexdigest(), signature)

@app.route('/registry/<string:relaypoint>', methods=['POST'])
def registry_webhook(relaypoint):
    if request.method == 'POST':
        remote_ip = request.remote_addr

        try:
            registry_secret = request.headers.get('X-Registry-Secret')
            payload = request.get_json()
        except:
            return abort(400)

        r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
        src = r.get(relaypoint + ":allowed_ip")
        destinations = r.smembers(relaypoint + ":destinations")
        token = r.get(relaypoint + ":token")

        if (src is None or src != remote_ip or registry_secret != token):
            return abort(403)

        q = Queue(connection=StrictRedis(host='redis', port=6379, db=1))
        q.enqueue('relay.posthook', payload, destinations)
        return "Thanks for the work, Docker Registry!"
    else:
        abort(404)

@app.route('/dockerhub/<string:relaypoint>', methods=['POST'])
def dockerhub_webhook(relaypoint):
    if request.method == 'POST':
        try:
            payload = request.get_json()
            repo = payload['repository']['repo_name']
        except:
            return abort(400)

        r = StrictRedis(host='redis', port=6379, db=0, decode_responses=True)
        allowed_repos = r.smembers(relaypoint + ":allowed_repos")
        destinations = r.smembers(relaypoint + ":destinations")

        if repo not in allowed_repos:
            return abort(403)

        q = Queue(connection=StrictRedis(host='redis', port=6379, db=1))
        q.enqueue('relay.posthook', payload, destinations)
        return "Thanks for the work, DockerHub!"
    else:
        abort(404)

if __name__ == '__main__':
    app.run()
