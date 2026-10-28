# Test cases for ssrf.yml; run with: semgrep --test semgrep/
import urllib.request

import flask
import httpx
import requests
from flask import request

from ssrf_guard import Guard, validate_url
from ssrf_guard.integrations.httpx import guarded_client
from ssrf_guard.integrations.requests import guarded_session

app = flask.Flask(__name__)


@app.route("/a")
def fetch_requests():
    url = request.args.get("url")
    # ruleid: unguarded-request-to-user-url
    return requests.get(url, timeout=5).text


@app.route("/b")
def fetch_httpx():
    target = flask.request.json["target"]
    # ruleid: unguarded-request-to-user-url
    return httpx.post(target, json={}).text


@app.route("/c")
def fetch_urllib():
    # ruleid: unguarded-request-to-user-url
    return urllib.request.urlopen(request.form["u"]).read()


@app.route("/d")
def fetch_session():
    with requests.Session() as s:
        # ruleid: unguarded-request-to-user-url
        return s.get(request.values["u"], timeout=5).text


@app.route("/e")
def fetch_client():
    client = httpx.Client()
    # ruleid: unguarded-request-to-user-url
    return client.get("https://" + request.args["host"] + "/x").text


@app.route("/f")
def fetch_guarded_httpx():
    with guarded_client() as client:
        # ok: unguarded-request-to-user-url
        return client.get(request.args["url"]).text


@app.route("/g")
def fetch_guarded_requests():
    with guarded_session() as session:
        # ok: unguarded-request-to-user-url
        return session.get(request.args["url"], timeout=5).text


@app.route("/h")
def fetch_constant():
    # ok: unguarded-request-to-user-url
    return requests.get("https://api.example.com/status", timeout=5).text


def django_view(request):
    # ruleid: unguarded-request-to-user-url
    return requests.get(request.GET["next"], timeout=5)


def check_then_fetch(url: str) -> bytes:
    validate_url(url)
    # ruleid: validate-then-fetch-toctou
    return requests.get(url, timeout=5).content


def check_then_fetch_if(url: str) -> bytes:
    if not is_safe_url(url):
        raise ValueError(url)
    # ruleid: validate-then-fetch-toctou
    return httpx.get(url).content


def check_then_fetch_assigned(url: str) -> bytes:
    parsed = Guard().parse(url)
    print(parsed)
    # ruleid: validate-then-fetch-toctou
    return urllib.request.urlopen(url).read()


def pinned_fetch(url: str) -> bytes:
    target = Guard().resolve(url)
    # ok: validate-then-fetch-toctou
    return requests.get(target.pinned_url, headers={"Host": target.host_header}, timeout=5).content


def guarded_fetch(url: str) -> bytes:
    validate_url(url)  # early, user-friendly error
    with guarded_client() as client:
        # ok: validate-then-fetch-toctou
        return client.get(url).content


def is_safe_url(url: str) -> bool:
    return url.startswith("https://")


@app.route("/i")
def fetch_request_method():
    # ruleid: unguarded-request-to-user-url
    return requests.request("GET", request.args["url"], timeout=5).text
