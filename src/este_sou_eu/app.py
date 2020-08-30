import urllib.parse
import uuid
from datetime import datetime
from datetime import timedelta
from typing import List

import jwt
import mf2py
import requests
import toml
from bs4 import BeautifulSoup
from flask import abort
from flask import Flask
from flask import jsonify
from flask import request
from flask import redirect
from flask import render_template
from flask import Response
from flask import session
from flask import url_for
from flask_caching import Cache
from flask_dance.consumer import oauth_authorized  # requires blinker
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.twitter import make_twitter_blueprint, twitter
from webargs import fields, validate
from webargs.flaskparser import parser, use_kwargs
from werkzeug.datastructures import Headers


PROVIDERS = {
    "github": "https://github.com/",
    "twitter": "https://twitter.com/",
}


app = Flask(__name__)
app.config.from_file("config.toml", load=toml.load)
cache = Cache(app)

# XXX load only those configured
github_blueprint = make_github_blueprint(
    client_id=config["oauth"]["github"]["client_id"],
    client_secret=config["oauth"]["github"]["client_secret"],
)
app.register_blueprint(github_blueprint, url_prefix="/login")
twitter_blueprint = make_twitter_blueprint(
    api_key=config["oauth"]["twitter"]["api_key"],
    api_secret=config["oauth"]["twitter"]["api_secret"],
)
app.register_blueprint(twitter_blueprint, url_prefix="/login")


def get_client_info(client_id):
    redirect_urls = []

    response = requests.get(client_id)
    html = response.content

    metadata = mf2py.parse(doc=html)
    for item in metadata["items"]:
        if "h-app" in item["type"]:
            app_info = item["properties"]
            break
    else:
        app_info = {}

    # ensure URLs are absolute
    for prop in ["logo", "url", "photo"]:
        if prop not in app_info:
            break
        app_info[prop] = [
            urllib.parse.urljoin(client_id, url) for url in app_info[prop]
        ]

    if "Link" in response.headers:
        header = response.headers["Link"]
        links = requests.utils.parse_header_links(header)
        for link in links:
            if link["rel"] == "redirect_uri":
                redirect_urls.append(urllib.parse.urljoin(client_id, link["url"]))

    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("link", rel="redirect_uri")
    for link in links:
        redirect_urls.append(urllib.parse.urljoin(client_id, link["href"]))

    return app_info, redirect_urls


def find_profiles(me):
    response = requests.get(me)
    html = response.content

    soup = BeautifulSoup(html, "html.parser")
    anchors = soup.find_all("a", rel="me")
    profiles = {}
    for anchor in anchors:
        link = anchor["href"]
        # XXX try only those configured
        for provider, baseurl in PROVIDERS.items():
            if link.startswith(baseurl):
                profiles[provider] = link

    return profiles


@app.route("/")
def index():
    headers = Headers()
    headers.add("Link", f'<{config["me"]}/auth>; rel="authorization_endpoint"')
    headers.add("Link", f'<{config["me"]}/token>; rel="token_endpoint"')

    return render_template("hcard.html", config=config), headers


@app.route("/login", methods=["GET", "POST"])
def rel_me_auth():
    if request.method == "GET":
        if "payload" not in session:
            return render_template("login.html")
        me = session["payload"]["me"]
    else:
        args = parser.parse({"me": fields.URL(required=True)}, request, location="form")
        me = args["me"]

    # find supported profiles and use the first one
    profiles = find_profiles(me)
    if not profiles:
        abort(
            400,
            {
                "messages": [
                    f'Could not find a rel="me" link in {me} pointing to a valid profile ({", ".join(PROVIDERS)})'
                ]
            },
        )
    profile = list(profiles)[0]
    session["tentative_me"] = me
    session["profiles"] = profiles
    return redirect(url_for(f"{profile}.login"))


@oauth_authorized.connect
def authorized(blueprint, token):
    blueprint.token = token
    me = session["tentative_me"]
    profiles = session["profiles"]

    valid = False
    messages = []
    if github.authorized:
        url = profiles["github"]
        response = github.get("/user")
        github_info = response.json()
        if github_info["html_url"] == url:
            valid = True
        else:
            messages.append(
                f"Github URL ({github_info['html_url']}) is different than the one listed on {me} ({url})"
            )
    if twitter.authorized:
        url = profiles["twitter"]
        response = twitter.get("account/settings.json")
        twitter_info = response.json()
        screen_name = twitter_info["screen_name"]
        twitter_url = urllib.parse.urljoin(PROVIDERS["twitter"], screen_name)
        if twitter_url == url:
            valid = True
        else:
            messages.append(
                f"Twitter URL ({twitter_url}) is different than the one listed on {me} ({url})"
            )

    if not valid:
        abort(400, {"messages": messages})

    # store user's site
    session["me"] = me

    # continue authorization process
    if "payload" not in session:
        return redirect(url_for("index"))
    payload = session["payload"]
    return redirect(url_for("get_auth"), **payload)


@app.route("/logout", methods=["GET"])
def logout():
    session.pop("me", None)
    return redirect(url_for("index"))


@app.route("/auth", methods=["GET"])
@use_kwargs(
    {
        "response_type": fields.Str(required=True, validate=lambda rt: rt == "code"),
        "me": fields.URL(required=True),
        "client_id": fields.URL(required=True),
        "redirect_uri": fields.URL(required=True),
        "state": fields.Str(required=True),
        "scope": fields.DelimitedList(fields.Str(), delimiter=" ", missing=[]),
    },
    location="query",
)
def get_auth(
    response_type: str,
    me: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scope: List[str],
):
    payload = {
        "response_type": response_type,
        "me": me,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
    }

    # Make sure user is logged in; if not, set bookmark to resume process once
    # they've successfully logged in
    if "me" not in session:
        session["payload"] = payload
        return redirect(url_for("rel_me_auth"))

    # Make sure user is who they say they are
    if me != session["me"]:
        abort(403, {"messages": ['Invalid value for "me"']})

    # The authorization endpoint SHOULD fetch the client_id URL to retrieve
    # application information and the client's registered redirect URLs, see
    # Client Information Discovery for more information.
    app_info, redirect_urls = get_client_info(client_id)

    # If the URL scheme, host or port of the redirect_uri in the request do not
    # match that of the client_id, then the authorization endpoint SHOULD verify
    # that the requested redirect_uri matches one of the redirect URLs published
    # by the client, and SHOULD block the request from proceeding if not.
    parsed_client_id = urllib.parse.urlparse(client_id)
    parsed_redirect_uri = urllib.parse.urlparse(redirect_uri)
    if (
        parsed_client_id.scheme != parsed_redirect_uri.scheme
        or parsed_client_id.hostname != parsed_redirect_uri.hostname
        or parsed_client_id.port != parsed_redirect_uri.port
    ) and redirect_uri not in redirect_urls:
        abort(400, {"messages": ['Invalid value for "redirect_uri"']})

    # code - The authorization code generated by the authorization endpoint. The
    # code MUST expire shortly after it is issued to mitigate the risk of leaks,
    # and MUST be valid for only one use. A maximum lifetime of 10 minutes is
    # recommended. See OAuth 2.0 Section 4.1.2 for additional requirements on the
    # authorization code.
    code = uuid.uuid4()
    cache.set(code, payload, timeout=timedelta(minutes=10).total_seconds())
    url = f"{redirect_uri}?code={code}&state={state}"
    return render_template(
        "auth.html", app_info=app_info, me=me, scope=scope, redirect_url=url
    )


@app.route("/auth", methods=["POST"])
@use_kwargs(
    {
        "grant_type": fields.Str(
            required=True, validate=lambda gt: gt == "authorization_code"
        ),
        "code": fields.Str(required=True),
        "client_id": fields.URL(required=True),
        "redirect_uri": fields.URL(required=True),
    }
)
def post_auth(grant_type: str, code: str, client_id: str, redirect_uri: str):
    # The authorization endpoint verifies that the authorization code is valid,
    # has not yet been used, and that it was issued for the matching client_id
    # and redirect_uri.
    payload = cache.get(code)
    if not cache.delete(code):
        abort(400, {"messages": ["Token is invalid"]})

    if payload["client_id"] != client_id or payload["redirect_uri"] != redirect_uri:
        abort(400, {"messages": ["Token not valid for client_id/redirect_uri"]})

    return jsonify({"me": payload["me"]})


@app.route("/token", methods=["POST"])
@use_kwargs(
    {
        "grant_type": fields.Str(
            required=True, validate=lambda gt: gt == "authorization_code"
        ),
        "code": fields.Str(required=True),
        "client_id": fields.URL(required=True),
        "redirect_uri": fields.URL(required=True),
    }
)
def post_token(grant_type: str, code: str, client_id: str, redirect_uri: str):
    # The token endpoint needs to verify that the authorization code is valid,
    # and that it was issued for the matching client_id and redirect_uri, and
    # contains at least one scope. If the authorization code was issued with no
    # scope, the token endpoint MUST NOT issue an access token, as empty scopes
    # are invalid per Section 3.3 of OAuth 2.0 [RFC6749].
    payload = cache.get(code)
    if not cache.delete(code):
        abort(400, {"messages": ["Token is invalid"]})

    if payload["client_id"] != client_id or payload["redirect_uri"] != redirect_uri:
        abort(400, {"messages": ["Token not valid for client_id/redirect_uri"]})

    if not payload["scope"]:
        abort(400, {"messages": ["Invalid empty scope"]})

    access_token = jwt.encode(
        {
            "me": payload["me"],
            "client_id": payload["client_id"],
            "scope": payload["scope"],
        },
        config["JWT_SECRET"],
        algorithm="HS256",
    )
    cache.set(access_token, True)

    return jsonify(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "scope": payload["scope"],
            "me": payload["me"],
        }
    )


@app.route("/token", methods=["GET"])
def get_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        abort(401, {"messages": ["No valid authorization header found"]})

    access_token = auth_header.split(" ", 1)[1]

    if access_token not in cache:
        abort(400, {"messages": ["Invalid access token"]})

    payload = jwt.decode(access_token, config["JWT_SECRET"], algorithms=["HS256"])
    return jsonify(payload)


@app.route("/redirect", methods=["POST"])
@use_kwargs({"url": fields.URL(required=True)}, location="form")
def redirect_to_url(url: str):
    return redirect(url, code=302)


# Return validation errors as JSON
@app.errorhandler(422)
@app.errorhandler(400)
def handle_error(err):
    headers = err.data.get("headers", None)
    messages = err.data.get("messages", ["Invalid request."])
    if headers:
        return jsonify({"errors": messages}), err.code, headers
    else:
        return jsonify({"errors": messages}), err.code
