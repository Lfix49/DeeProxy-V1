#!/usr/bin/env python3
"""
DeeProxy v1.2.0 - public-use cloud proxy. Python standard library only.

Run:    python3 deeproxy.py
Open:   http://127.0.0.1:8080

Cloud-ready changes
  - Reads the hosting platform's PORT and binds to 0.0.0.0.
  - Allows visitors without an invite/password and creates a separate session per browser.
  - Keeps each visitor's upstream cookies and static cache isolated in memory.
  - Adds basic destination checks to block private-network/localhost targets.
  - Does not imitate browser TLS fingerprints or bypass site security checks.

What it does
  - Type a URL or search term; pages load through the proxy and links, images,
    stylesheets, forms and redirects keep going through it.
  - Keeps a separate in-memory cookie jar for each visitor. Cookies a site marks
    HttpOnly stay only in the proxy; ordinary ones are also handed to your browser
    so the site's scripts can read them (CSRF tokens etc.), just like on the real site.
  - Forwards requests that page scripts make to "/something" back to the real
    site, and relays WebSockets so live status displays work.
  - Speed: reused connections, gzip from the sites, cached images/fonts/CSS.
  - /reset clears the current visitor's saved logins, cache and browser cookies.
  - No visitor password or invite key is required. Sessions disappear when the service restarts.
  - /home always shows this start page (after you visit a site, plain "/" may be
    that site's own front page, because the address bar shows the site's real path).
"""
import base64
import gzip
import hashlib
import ipaddress
import http.client
import http.cookiejar
import json
import os
import re
import select
import secrets
import socket
import ssl
import threading
import time
import urllib.request
from html import escape as html_escape, unescape as html_unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlparse

VERSION = "1.2.0"
# Cloud hosts (including Render) provide PORT and require 0.0.0.0.
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
COOKIE_SECURE = os.environ.get("DEEPROXY_SECURE_COOKIE", "1").lower() not in ("0", "false", "no", "off")
SESSION_MAX_AGE = 60 * 60 * 24 * 30
CACHE_SECONDS = 600
STYLE = """<style>
  :root{--bg:#f6f7fb;--fg:#14141a;--muted:#6b6f80;--line:#e3e5ef;--card:#fff;
        --accent:#4f46e5;--accent-fg:#fff;--ring:rgba(79,70,229,.22)}
  @media (prefers-color-scheme:dark){
    :root{--bg:#0d0e14;--fg:#f1f2f8;--muted:#9094a8;--line:#262838;--card:#151722;
          --accent:#818cf8;--accent-fg:#0d0e14;--ring:rgba(129,140,248,.25)}
  }
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;
       background:radial-gradient(900px 520px at 12% -10%,rgba(99,102,241,.20),transparent 60%),
                  radial-gradient(800px 520px at 100% 0%,rgba(236,72,153,.15),transparent 60%),
                  radial-gradient(700px 500px at 50% 120%,rgba(20,184,166,.14),transparent 60%),
                  var(--bg);
       color:var(--fg);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",
       Roboto,sans-serif;-webkit-font-smoothing:antialiased}
  main{width:min(560px,90vw)}
  h1{font-size:15px;font-weight:600;letter-spacing:.02em;margin:0 0 28px;color:var(--muted)}
  form{display:flex;align-items:center;gap:8px;padding:6px;background:var(--card);
       border:1px solid var(--line);border-radius:12px;
       transition:border-color .15s,box-shadow .15s}
  form:focus-within{border-color:var(--accent);box-shadow:0 0 0 4px var(--ring)}
  input{flex:1;min-width:0;padding:11px 12px;border:0;outline:0;background:transparent;
        color:var(--fg);font:inherit;font-size:16px}
  input::placeholder{color:var(--muted)}
  button{padding:10px 18px;border:0;border-radius:8px;background:var(--accent);
         color:var(--accent-fg);font:inherit;font-size:14px;font-weight:500;cursor:pointer;
         transition:opacity .15s}
  button:hover{opacity:.85}
  footer{margin-top:20px;font-size:13px}
  a{color:var(--muted);text-decoration:none;transition:color .15s}
  a:hover{color:var(--fg)}
  pre{white-space:pre-wrap;word-break:break-word;margin:16px 0 0;padding:14px 16px;
      background:var(--card);border:1px solid var(--line);border-radius:10px;
      font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}
  h2{font-size:22px;font-weight:600;letter-spacing:-.01em;margin:0}
</style>"""

# Quick links on the home page: (name, address, letter, tile color)
QUICK_LINKS = [
    ("ChatGPT",    "https://chatgpt.com",          "C", "#10a37f"),
    ("Aternos",    "https://aternos.org",          "A", "#e5484d"),
    ("Google",     "https://www.google.com",       "G", "#4285f4"),
    ("YouTube",    "https://www.youtube.com",      "Y", "#ff0033"),
    ("DuckDuckGo", "https://duckduckgo.com",       "D", "#de5833"),
    ("Wikipedia",  "https://en.wikipedia.org",     "W", "#636466"),
    ("Reddit",     "https://www.reddit.com",       "R", "#ff4500"),
    ("GitHub",     "https://github.com",           "G", "#6e40c9"),
    ("Discord",    "https://discord.com/app",      "D", "#5865f2"),
    ("Spotify",    "https://open.spotify.com",     "S", "#1db954"),
    ("Twitch",     "https://www.twitch.tv",        "T", "#9146ff"),
    ("Minecraft",  "https://www.minecraft.net",    "M", "#62a43c"),
]

HOME_STYLE = """<style>
  main.home{width:min(720px,92vw);padding:40px 0}
  .hero{text-align:center;margin-bottom:28px}
  .hero h1{font-size:34px;font-weight:700;letter-spacing:-.03em;margin:0 0 8px;color:var(--fg)}
  .hero h1 span{background:linear-gradient(90deg,#6366f1,#ec4899,#f59e0b);
                -webkit-background-clip:text;background-clip:text;color:transparent}
  .hero p{margin:0;color:var(--muted);font-size:15px}
  .home form{box-shadow:0 8px 30px rgba(79,70,229,.10)}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;
        margin-top:28px}
  .tile{display:flex;align-items:center;gap:12px;padding:12px 14px;background:var(--card);
        border:1px solid var(--line);border-radius:14px;color:var(--fg);font-size:14px;
        font-weight:500;transition:transform .15s,box-shadow .15s,border-color .15s}
  .tile:hover{transform:translateY(-2px);border-color:var(--c);
              box-shadow:0 8px 22px -8px var(--c);color:var(--fg)}
  .ico{position:relative;overflow:hidden;flex:none;width:36px;height:36px;border-radius:10px;
       display:grid;place-items:center;background:var(--c);color:#fff;font-weight:700;
       font-size:16px}
  .ico img{position:absolute;inset:0;width:100%;height:100%;padding:6px;object-fit:contain;
           background:#fff}
  .home footer{text-align:center;margin-top:28px}
</style>"""

def _icon(url):
    """Each site's own favicon, fetched through this proxy (the colored letter
    underneath shows if the picture can't be loaded)."""
    fav = "https://www.google.com/s2/favicons?sz=64&domain=" + urlparse(url).netloc
    return f'<img src="/go?url={quote(fav, safe="")}" alt="" onerror="this.remove()">'


_tiles = "".join(
    f'<a class="tile" style="--c:{color}" href="/go?url={quote(url, safe="")}">'
    f'<span class="ico">{letter}{_icon(url)}</span>{name}</a>'
    for name, url, letter, color in QUICK_LINKS
)

HOME = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeeProxy</title>
""" + STYLE + HOME_STYLE + """
<main class="home">
  <div class="hero">
    <h1><span>DeeProxy</span></h1>
    <p>Type a web address or search for anything.</p>
  </div>
  <form action="/go" method="get">
    <input name="url" placeholder="Enter a URL or search term" autocomplete="off"
           autocapitalize="off" spellcheck="false" autofocus>
    <button>Go</button>
  </form>
  <div class="grid">""" + _tiles + """</div>
  <footer><a href="/reset">Clear logins, cache and cookies</a>
    <span style="color:var(--muted)"> &middot; v""" + VERSION + """</span></footer>
</main>"""


def error_page(title, detail=""):
    from html import escape
    return ("""<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>""" + escape(title) + "</title>" + STYLE + "<main><h2>" + escape(title) + "</h2>"
            + (f"<pre>{escape(detail)}</pre>" if detail else "")
            + '<footer><a href="/home">&larr; Back</a></footer></main>').encode()

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SKIP = ("javascript:", "data:", "mailto:", "tel:", "blob:", "#", "about:")
ATTR = re.compile(
    r'''((?<![\w-])(?:href|src|action|poster|data-src|data-lazy-src|data-original|'''
    r'''data-bg|data-background)\s*=\s*)(["'])(.*?)\2''', re.I | re.S)
SRCSET = re.compile(r'''((?<![\w-])(?:srcset|data-srcset)\s*=\s*)(["'])(.*?)\2''', re.I | re.S)
STYLE_ATTR = re.compile(r'''((?<![\w-])style\s*=\s*)(["'])(.*?)\2''', re.I | re.S)
STYLE_BLOCK = re.compile(r"(<style\b[^>]*>)(.*?)(</style>)", re.I | re.S)
BASE_TAG = re.compile(r"<base\b[^>]*>", re.I)
META_REFRESH = re.compile(
    r'''(<meta[^>]+http-equiv=["']?refresh[^>]*content=["'][^"'>]*?url\s*=\s*)([^"'>]+)''', re.I)
FORM = re.compile(r"<form\b[^>]*>", re.I)
CSS_URL = re.compile(r'''url\(\s*(["']?)(.*?)\1\s*\)''', re.I)
CSS_IMPORT = re.compile(r'''@import\s+(["'])(.*?)\1''', re.I)

# Injected into every proxied page. Pages open live connections (WebSockets)
# and load things from other sites straight from the page's scripts, which
# skips the proxy (no login, blocked fonts/images/data, a page that looks
# broken). This sends all of that through the proxy instead.
WS_SHIM = r"""<script>(function(){
var W=window.WebSocket;
function P(u,p){try{var a=new URL(u,location.href);
if((a.protocol==='wss:'||a.protocol==='ws:')&&a.host!==location.host){
u='ws://'+location.host+'/__ws?url='+encodeURIComponent(a.href);}}catch(e){}
return p===undefined?new W(u):new W(u,p);}
P.prototype=W.prototype;P.CONNECTING=0;P.OPEN=1;P.CLOSING=2;P.CLOSED=3;
window.WebSocket=P;
function R(u){try{var s=String(u);if(/^(data|blob|javascript|about|mailto|tel):/i.test(s))return u;
var a=new URL(s,location.href);
if((a.protocol==='http:'||a.protocol==='https:')&&a.origin!==location.origin)
return '/go?url='+encodeURIComponent(a.href);}catch(e){}return u;}
var F=window.fetch;
if(F)window.fetch=function(i,o){try{
if(typeof i==='string'||i instanceof URL)i=R(i);
else if(i&&i.url){i=new Request(R(i.url),i);}}catch(e){}
return F.call(this,i,o);};
var X=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){arguments[1]=R(u);return X.apply(this,arguments);};
function hook(C,prop){try{var d=Object.getOwnPropertyDescriptor(C.prototype,prop);
if(!d||!d.set)return;
Object.defineProperty(C.prototype,prop,{configurable:true,enumerable:d.enumerable,
get:d.get,set:function(v){d.set.call(this,R(v));}});}catch(e){}}
hook(HTMLImageElement,'src');hook(HTMLScriptElement,'src');hook(HTMLLinkElement,'href');
hook(HTMLIFrameElement,'src');hook(HTMLSourceElement,'src');hook(HTMLMediaElement,'src');
var SA=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){
try{var t=this.tagName,k=String(n).toLowerCase();
if(t!=='A'&&t!=='FORM'&&(k==='src'||(k==='href'&&t==='LINK')))v=R(v);}catch(e){}
return SA.call(this,n,v);};
var PAGE=__PAGE__;
/* Show the site's real path in the address bar so single-page apps (ChatGPT,
   TikTok, ...) route correctly instead of seeing "/go". */
try{if(window.top===window&&location.pathname==='/go'){var pb=new URL(PAGE);
history.replaceState(history.state,'',pb.pathname+pb.search+location.hash);}}catch(e){}
/* A service worker would take over the proxy's whole address and break every site. */
try{if(navigator.serviceWorker){navigator.serviceWorker.register=function(){
return Promise.reject(new Error('service workers are disabled by the proxy'));};}}catch(e){}
/* Cookies set by scripts: a Domain=.site.com / Secure / SameSite=None attribute makes
   the browser throw the cookie away on the proxy's address. */
try{var CD=Object.getOwnPropertyDescriptor(Document.prototype,'cookie'),PFX='__PFX__';
/* Every proxied site shares this one address, so each site's cookies get their own
   name prefix; the page only ever sees (and writes) its own, without the prefix. */
Object.defineProperty(document,'cookie',{configurable:true,
get:function(){var o=[];CD.get.call(document).split(/;\s*/).forEach(function(c){
if(c.indexOf(PFX)===0)o.push(c.slice(PFX.length));});return o.join('; ');},
set:function(v){v=String(v).replace(/;\s*domain=[^;]*/ig,'').replace(/;\s*secure\s*(?=;|$)/ig,'')
.replace(/;\s*samesite=[^;]*/ig,'').replace(/;\s*path=[^;]*/ig,'').replace(/^\s+/,'');
CD.set.call(document,PFX+v+'; path=/');}});}catch(e){}
/* Links that scripts create pointing at other sites must stay inside the proxy. */
document.addEventListener('click',function(e){try{
if(e.defaultPrevented||e.button||e.metaKey||e.ctrlKey||e.shiftKey)return;
var a=e.target&&e.target.closest&&e.target.closest('a[href]');if(!a)return;
var h=a.getAttribute('href'),n=R(h);
if(n!==h&&n.indexOf('/go?url=')===0){e.preventDefault();
if(a.target&&a.target!=='_self')window.open(n,a.target);else location.href=n;}}catch(x){}},true);
var WO=window.open;
window.open=function(u){try{if(u)arguments[0]=R(u);}catch(e){}return WO.apply(this,arguments);};
})();</script>"""


# ---------------------------------------------------------------- URL helpers
def prox(url):
    return "/go?url=" + quote(url, safe="")


def unwrap(url):
    """Search results are wrapped in DuckDuckGo's own redirect
    (duckduckgo.com/l/?uddg=REAL_URL&rut=...). That redirect is what was
    failing with 400/404, so skip it and go straight to the real site."""
    try:
        u = urlparse(url)
        if u.netloc.endswith("duckduckgo.com") and u.path.startswith("/l/"):
            real = dict(parse_qsl(u.query)).get("uddg")
            if real:
                if real.startswith("//"):
                    real = "https:" + real
                return real
    except Exception:
        pass
    return url


def link(base, val):
    """Turn a link found in a page into a proxied link. Attribute values in
    HTML write '&' as '&amp;', so undo that first, otherwise every link with
    a query string gets mangled (?a=1&amp;b=2 -> a parameter called 'amp;b')."""
    return prox(unwrap(urljoin(base, html_unescape(val).strip())))


def normalize(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        if "." in raw and " " not in raw:
            raw = "https://" + raw
        else:
            raw = "https://duckduckgo.com/html/?q=" + quote(raw)
    return raw


# ------------------------------------------------------------------ rewriting
def rewrite_html(html, base):
    page_url = base
    # A <base href> changes what every relative link means; honor it, then drop it.
    bm = BASE_TAG.search(html)
    if bm:
        hm = re.search(r'href\s*=\s*(["\'])(.*?)\1', bm.group(0), re.I | re.S)
        if hm:
            base = urljoin(base, hm.group(2).strip())
        html = BASE_TAG.sub("", html)

    def attr(m):
        val = html_unescape(m.group(3)).strip()
        if not val or val.lower().startswith(SKIP):
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}{link(base, val)}{m.group(2)}"

    def srcset(m):
        parts = []
        for item in re.split(r"(?<=[0-9][xw]),\s*|,\s+", html_unescape(m.group(3)).strip()):
            bits = item.strip().split(None, 1)
            if not bits:
                continue
            u = bits[0]
            if not u.lower().startswith(SKIP):
                u = link(base, u)
            parts.append(" ".join([u] + bits[1:]))
        return f"{m.group(1)}{m.group(2)}{', '.join(parts)}{m.group(2)}"

    def style_attr(m):
        return f"{m.group(1)}{m.group(2)}{rewrite_css(m.group(3), base, q=chr(39))}{m.group(2)}"

    def style_block(m):
        return m.group(1) + rewrite_css(m.group(2), base) + m.group(3)

    def refresh(m):
        return m.group(1) + link(base, m.group(2))

    def form(m):
        tag = m.group(0)
        if re.search(r'method\s*=\s*["\']?post', tag, re.I):
            return tag
        am = re.search(r'action\s*=\s*(["\'])(.*?)\1', tag, re.I | re.S)
        target = urljoin(base, html_unescape(am.group(2))) if am else base
        return tag + f'<input type="hidden" name="__url" value="{html_escape(target, quote=True)}">'

    html = FORM.sub(form, html)          # GET forms need their real target first
    html = STYLE_BLOCK.sub(style_block, html)   # <style> blocks: fonts, backgrounds
    html = STYLE_ATTR.sub(style_attr, html)     # style="background:url(...)"
    html = SRCSET.sub(srcset, html)             # responsive images
    html = ATTR.sub(attr, html)
    html = META_REFRESH.sub(refresh, html)
    html = re.sub(r"<meta[^>]+http-equiv=[\"']?content-security-policy[^>]*>", "", html, flags=re.I)
    html = re.sub(r'\s(integrity|nonce)=("[^"]*"|\'[^\']*\')', "", html, flags=re.I)
    m = re.search(r"<head[^>]*>", html, re.I)
    shim = (WS_SHIM.replace("__PAGE__", json.dumps(page_url).replace("</", "<\\/"))
            .replace("__PFX__", ck_prefix(site_tag(page_url))))
    if m:
        return html[:m.end()] + shim + html[m.end():]
    return shim + html


def rewrite_css(css, base, q='"'):
    def sub(m):
        val = m.group(2).strip()
        if not val or val.lower().startswith(SKIP):
            return m.group(0)
        return f'url({q}{prox(urljoin(base, val))}{q})'

    def imp(m):
        val = m.group(2).strip()
        if not val or val.lower().startswith(SKIP):
            return m.group(0)
        return f'@import {q}{prox(urljoin(base, val))}{q}'
    return CSS_IMPORT.sub(imp, CSS_URL.sub(sub, css))


# -------------------------------------------------------------------- cookies
# Each authenticated browser gets its own server-side cookie jar. Sessions are
# intentionally memory-only: restarting the service clears all saved logins.
class UserSession:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.cache = {}
        self.lock = threading.RLock()
        self.created = time.time()

SESSIONS = {}
SESSIONS_LOCK = threading.RLock()

def get_jar():
    jar = getattr(_local, "jar", None)
    if jar is None:
        raise RuntimeError("No authenticated user session is active")
    return jar


def site_tag(url_or_netloc):
    """Short id of a site (its registrable domain), so cookies of tiktok.com and
    www.tiktok.com share a tag but never mix with other sites."""
    n = url_or_netloc
    if "://" in n:
        n = urlparse(n).netloc
    return hashlib.md5(_etld1(n).lower().encode()).hexdigest()[:8]


def ck_prefix(tag):
    return f"__px{tag}_"


def browser_cookies(headers, tag):
    """The cookies your browser holds for ONE site (those with that site's prefix),
    prefix removed. Duplicates are dropped (newest wins) and the total is capped,
    because a huge Cookie header makes servers answer "400 Bad Request"."""
    pre = ck_prefix(tag)
    seen = {}
    for c in headers.get("Cookie", "").split(";"):
        c = c.strip()
        if c.startswith(pre):
            name, _, val = c[len(pre):].partition("=")
            if name:
                seen[name] = f"{name}={val}"     # later duplicates replace earlier ones
    kept, size = [], 0
    for c in reversed(list(seen.values())):    # keep the newest first
        if size + len(c) + 2 > 7000:
            continue
        kept.append(c)
        size += len(c) + 2
    return "; ".join(reversed(kept))


def cookie_base(headers):
    """The last real page you opened, remembered in a cookie on the proxy itself."""
    for part in headers.get("Cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "__pxbase":
            return unquote(v)
    return ""


def real_referer(headers):
    """Turn the browser's Referer (a proxy URL) back into the real page URL.
    If the page changed its own address (pushState), fall back to the last
    real page we served."""
    ref = headers.get("Referer", "")
    found = ""
    try:
        q = dict(parse_qsl(urlparse(ref).query))
        found = q.get("__url") or q.get("url") or ""
    except Exception:
        pass
    return normalize(found) if found else cookie_base(headers)


def page_of(headers, path):
    """The real page a request comes from. For a top-level load of a site path
    (a reload, or a script doing location.href='/x') the browser's Referer can be
    the page BEFORE this one, so the remembered current page wins there."""
    if urlparse(path).path != "/go" and headers.get("Sec-Fetch-Dest", "") == "document":
        return cookie_base(headers) or real_referer(headers)
    return real_referer(headers)


def merged_cookies(url, headers, page_url=None):
    """Saved cookies for `url`, plus the cookies your browser holds for that same
    site (set by its scripts, or mirrored from its Set-Cookie headers; sub-domains
    count as the same site). A cookie the browser has overrides a saved one with
    the same name, so the site never gets two copies."""
    tmp = urllib.request.Request(url)
    get_jar().add_cookie_header(tmp)
    saved = [c.strip() for c in (tmp.get_header("Cookie") or "").split(";") if c.strip()]
    mine = [c for c in browser_cookies(headers, site_tag(url)).split("; ") if c]
    names = {c.partition("=")[0] for c in mine}
    saved = [c for c in saved if c.partition("=")[0] not in names] + mine
    return "; ".join(saved)


def mirror_cookies(set_cookie_lines, tag):
    """Turn a site's Set-Cookie headers into ones the browser will accept on the
    proxy's address. HttpOnly cookies are NOT passed on (the proxy keeps them);
    the rest are, so the site's scripts can read them (CSRF tokens, ids...)."""
    out = []
    for raw in set_cookie_lines:
        parts = [p.strip() for p in raw.split(";")]
        name, _, value = parts[0].partition("=")
        name = name.strip()
        if not name or "=" not in parts[0]:
            continue
        if name == "__pxbase":
            continue
        attrs = {}
        for p in parts[1:]:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
        if "httponly" in attrs:
            continue
        c = f"{ck_prefix(tag)}{name}={value}; Path=/"
        if attrs.get("max-age"):
            c += f"; Max-Age={attrs['max-age']}"
        elif attrs.get("expires"):
            c += f"; Expires={attrs['expires']}"
        out.append(c)
    return out


# Request headers that must NOT be copied from the browser to the real site.
_DROP = {"host", "connection", "keep-alive", "proxy-connection", "proxy-authorization",
         "te", "trailer", "transfer-encoding", "upgrade", "content-length", "expect",
         "accept-encoding", "cookie", "origin", "referer", "sec-fetch-site",
         "if-none-match", "if-modified-since", "if-range"}
# Response headers worth handing back (video seeking, downloads).
_PASS_RESP = ("Content-Range", "Accept-Ranges", "Content-Disposition", "Content-Language")


_TWO_PART = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp",
             "co.nz", "co.in", "com.br", "com.mx", "com.tr", "com.cn", "co.za", "com.sg",
             "com.hk", "co.kr", "com.ar", "com.tw"}


def _etld1(netloc):
    labels = netloc.split(":")[0].split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]).lower() in _TWO_PART:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def upstream_headers(src, target, referer, method):
    """Everything the browser sent (Authorization, CSRF tokens, sec-ch-ua, Range,
    custom X-... headers) except the proxy-specific ones, with Origin, Referer and
    Sec-Fetch-Site rewritten to what the real site would have seen."""
    h = {k: v for k, v in src.items()
         if k.lower() not in _DROP and not k.lower().startswith("x-forwarded")}
    h["Accept-Encoding"] = "gzip"
    have = {k.lower() for k in h}
    for k, v in (("User-Agent", "Mozilla/5.0"), ("Accept", "*/*"),
                 ("Accept-Language", "en-US,en;q=0.9")):
        if k.lower() not in have:
            h[k] = v
    t = urlparse(target)
    if referer:
        h["Referer"] = referer
    if method not in ("GET", "HEAD") or src.get("Origin"):
        o = urlparse(referer) if referer else t
        h["Origin"] = f"{o.scheme}://{o.netloc}"
    if src.get("Sec-Fetch-Mode"):
        rn = urlparse(referer).netloc if referer else ""
        if not rn:
            fs = "none"
        elif rn == t.netloc:
            fs = "same-origin"
        elif _etld1(rn) == _etld1(t.netloc):
            fs = "same-site"
        else:
            fs = "cross-site"
        h["Sec-Fetch-Site"] = fs
    return h


# ------------------------------------------------------- talking to real sites
_local = threading.local()   # one set of open connections per thread


def fetch_plain(target, method, body, headers):
    """Send the request to the real site over a reused connection. No auto-redirects.
    Returns (status, response headers, body, the site's Set-Cookie lines)."""
    req = urllib.request.Request(target)   # only here so the cookie jar can read the reply
    u = urlparse(target)
    path = quote((u.path or "/") + ("?" + u.query if u.query else ""),
                 safe="/%:@!$&'()*+,;=?~-._")
    key = (u.scheme, u.netloc)
    pool = getattr(_local, "pool", None)
    if pool is None:
        pool = _local.pool = {}

    for attempt in (0, 1):
        conn = pool.get(key)
        reused = conn is not None
        if conn is None:
            cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
            conn = cls(u.netloc, timeout=20)
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read()
            if data and (r.headers.get("Content-Encoding") or "").lower() == "gzip":
                data = gzip.decompress(data)
        except (http.client.HTTPException, OSError):
            conn.close()
            pool.pop(key, None)
            if reused and attempt == 0:
                continue  # the idle connection had gone stale; retry on a fresh one
            raise
        if r.will_close:
            conn.close()
            pool.pop(key, None)
        else:
            pool[key] = conn
        get_jar().extract_cookies(r, req)
        return r.status, r.headers, data, (r.headers.get_all("Set-Cookie") or [])


def is_static(ctype):
    return ctype.startswith("image/") or "font" in ctype or "text/css" in ctype


# Basic SSRF protection: only public HTTP(S) destinations are accepted. This
# blocks localhost, private LANs, link-local/cloud metadata IPs and unusual ports.
def safe_destination(url):
    try:
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            return False
        if u.username or u.password:
            return False
        port = u.port or (443 if u.scheme == "https" else 80)
        if port not in (80, 443):
            return False
        host = u.hostname.rstrip(".").lower()
        if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost") or host.endswith(".local"):
            return False
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        return bool(addresses) and all(a.is_global for a in addresses)
    except Exception:
        return False


def session_id_from(headers):
    for part in headers.get("Cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "__deesid":
            return v
    return ""


# -------------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep browser connections open between requests

    def log_message(self, fmt, *args):
        # Do not write the private invite key into hosting logs.
        message = fmt % args
        message = re.sub(r"([?&]key=)[^&\s]+", r"\1[redacted]", message)
        print(self.address_string(), message)

    def require_session(self):
        """Create or retrieve a visitor session without asking for a password."""
        sid = session_id_from(self.headers)
        with SESSIONS_LOCK:
            session = SESSIONS.get(sid) if sid else None
            if session and time.time() - session.created > SESSION_MAX_AGE:
                SESSIONS.pop(sid, None)
                session = None
            if not session:
                sid = secrets.token_urlsafe(32)
                session = UserSession()
                SESSIONS[sid] = session
                cookie = f"__deesid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_MAX_AGE}"
                if COOKIE_SECURE:
                    cookie += "; Secure"
                self._new_session_cookie = cookie
        self.session = session
        _local.jar = session.jar
        return True

    def send_response(self, code, message=None):
        super().send_response(code, message)
        cookie = getattr(self, "_new_session_cookie", None)
        if cookie:
            self.send_header("Set-Cookie", cookie)
            self._new_session_cookie = None

    def send_bytes(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            for item in (v if isinstance(v, list) else [v]):
                self.send_header(k, item)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        self.require_session()
        if parsed.path == "/__ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            return self.handle_ws(parsed)
        if parsed.path == "/reset":
            return self.handle_reset()
        self.handle_request("GET")

    def do_POST(self):
        self.require_session()
        self.handle_request("POST")

    def do_PUT(self):
        self.require_session()
        self.handle_request("PUT")

    def do_PATCH(self):
        self.require_session()
        self.handle_request("PATCH")

    def do_DELETE(self):
        self.require_session()
        self.handle_request("DELETE")

    def do_HEAD(self):
        self.require_session()
        self.handle_request("HEAD")

    # -- reset ---------------------------------------------------------------
    def handle_reset(self):
        get_jar().clear()
        self.session.cache.clear()
        sid = session_id_from(self.headers)
        with SESSIONS_LOCK:
            SESSIONS.pop(sid, None)
        self._new_session_cookie = None
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        for part in self.headers.get("Cookie", "").split(";"):
            name = part.split("=")[0].strip()
            if name:
                self.send_header("Set-Cookie", f"{name}=; Max-Age=0; Path=/")
        self.end_headers()

    # -- websockets ----------------------------------------------------------
    def handle_ws(self, parsed):
        """Relay a WebSocket between your browser and the real site.
        Both sides get their own handshake; after that the frames are copied
        across untouched."""
        target = dict(parse_qsl(parsed.query)).get("url", "")
        u = urlparse(target)
        if u.scheme not in ("ws", "wss") or not u.netloc:
            return self.send_bytes(400, b"bad websocket url", "text/plain")
        http_target = ("https" if u.scheme == "wss" else "http") + "://" + u.netloc + (u.path or "/")
        if not safe_destination(http_target):
            return self.send_bytes(403, b"websocket destination is not allowed", "text/plain")
        _local.jar = self.session.jar
        secure = u.scheme == "wss"
        port = u.port or (443 if secure else 80)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        http_url = ("https" if secure else "http") + "://" + u.netloc + (u.path or "/")
        cookies = merged_cookies(http_url, self.headers, cookie_base(self.headers))

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {u.netloc}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}",
            "Sec-WebSocket-Version: 13",
            f"Origin: {'https' if secure else 'http'}://{u.netloc}",
            f"User-Agent: {self.headers.get('User-Agent', 'Mozilla/5.0')}",
        ]
        if self.headers.get("Sec-WebSocket-Protocol"):
            lines.append(f"Sec-WebSocket-Protocol: {self.headers['Sec-WebSocket-Protocol']}")
        if cookies:
            lines.append(f"Cookie: {cookies}")

        up = None
        try:
            up = socket.create_connection((u.hostname, port), timeout=15)
            if secure:
                up = ssl.create_default_context().wrap_socket(up, server_hostname=u.hostname)
            up.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = up.recv(4096)
                if not chunk:
                    raise OSError("site closed the connection during the handshake")
                buf += chunk
        except Exception as e:
            if up:
                up.close()
            print(f"   [websocket] could not connect to {target}: {e}")
            return self.send_bytes(502, f"websocket failed: {e}".encode(), "text/plain")

        head, _, rest = buf.partition(b"\r\n\r\n")
        head_lines = head.decode(errors="replace").split("\r\n")
        if " 101 " not in head_lines[0] + " ":
            up.close()
            print(f"   [websocket] site refused: {head_lines[0]}  ({target})")
            return self.send_bytes(502, f"site refused websocket: {head_lines[0]}".encode(), "text/plain")

        chosen = ""
        for l in head_lines[1:]:
            k, _, v = l.partition(":")
            if k.strip().lower() == "sec-websocket-protocol":
                chosen = v.strip()
        accept = base64.b64encode(hashlib.sha1(
            (self.headers.get("Sec-WebSocket-Key", "") + WS_GUID).encode()).digest()).decode()
        reply = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket",
                 "Connection: Upgrade", f"Sec-WebSocket-Accept: {accept}"]
        if chosen:
            reply.append(f"Sec-WebSocket-Protocol: {chosen}")
        print(f"   [websocket] connected: {target}")
        self.close_connection = True
        a = self.connection
        try:
            a.sendall(("\r\n".join(reply) + "\r\n\r\n").encode() + rest)
            up.settimeout(None)
            a.settimeout(None)
            while True:
                if secure and up.pending():
                    ready = [up]  # data already decrypted and waiting
                else:
                    ready, _, _ = select.select([a, up], [], [], 60)
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is a else a).sendall(data)
        except OSError:
            pass
        finally:
            up.close()
            print(f"   [websocket] closed: {target}")

    # -- normal requests -----------------------------------------------------
    def resolve_target(self, parsed):
        """Work out which real URL this request is for. None = unknown."""
        if parsed.path == "/go":
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if "__url" in params:  # a GET form submitted from a proxied page
                target = params.pop("__url")
                if params:
                    target += ("&" if "?" in target else "?") + urlencode(params)
                return target
            return unwrap(normalize(params.get("url", "")))
        # A page script asked for something like /account/login on OUR address.
        # Use the page it came from to find the real site.
        ref = page_of(self.headers, self.path)
        if not ref:
            print(f"   [proxy 404] no idea which site {parsed.path} belongs to "
                  f"(Referer={self.headers.get('Referer')!r}, "
                  f"saved page={'yes' if cookie_base(self.headers) else 'no'})")
            return None
        target = urljoin(ref, self.path)
        print(f"   [forward] {parsed.path} -> {target}")
        return target

    def site_root(self, dest):
        """Plain "/" is the proxy's start page, unless the site you're on lives at
        its own "/" (its address bar path was set to the real one)."""
        base = cookie_base(self.headers)
        if not base:
            return ""
        if dest != "document":
            return base
        return base if urlparse(base).path in ("", "/") else ""

    def handle_request(self, method):
        _local.jar = self.session.jar
        with self.session.lock:
            return self._handle_request_locked(method)

    def _handle_request_locked(self, method):
        cache = self.session.cache
        parsed = urlparse(self.path)
        dest = self.headers.get("Sec-Fetch-Dest", "document")
        if parsed.path == "/home" or (parsed.path == "/" and not self.site_root(dest)):
            return self.send_bytes(200, HOME.encode(),
                                   extra={"Set-Cookie": "__pxbase=; Max-Age=0; Path=/"})
        if parsed.path.startswith("/cdn-cgi/rum"):
            return self.send_bytes(204, b"")  # Cloudflare analytics ping only; the
                                              # rest of /cdn-cgi/ (verification) is forwarded
        target = self.resolve_target(parsed)
        if target is None:
            return self.send_bytes(404, error_page("Page not found"))
        if not safe_destination(target):
            return self.send_bytes(403, error_page("Destination blocked", "Only public HTTP/HTTPS websites on ports 80 and 443 are allowed."))

        if method == "GET" and target in cache:
            ts, ccode, cctype, cdata = cache[target]
            if time.time() - ts < CACHE_SECONDS:
                return self.send_bytes(ccode, cdata, cctype,
                                       {"Cache-Control": f"max-age={CACHE_SECONDS}"})

        body = None
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))

        referer = page_of(self.headers, self.path)
        headers = upstream_headers(self.headers, target, referer, method)
        cookies = merged_cookies(target, self.headers, referer)
        if cookies:
            headers["Cookie"] = cookies

        try:
            code, rheaders, data, set_cookies = fetch_plain(target, method, body, headers)
        except Exception as e:
            return self.send_bytes(502, error_page("Couldn't reach that site", f"{target}\n\n{e}"))

        print(f"   [site said {code}] {target[:110]}")
        if code in (403, 429, 503) and ("challenge" in (rheaders.get("cf-mitigated") or "").lower()
                                        or b"Just a moment" in data[:6000]):
            print("   [blocked] the site answered with a bot-check (Cloudflare) page; "
                  "it can't be passed from a script, only by a real browser connection")

        # Cookies the site set: HttpOnly ones stay in the proxy's jar, the rest are
        # also given to the browser so the site's scripts can read them.
        extra = {}
        mirrored = mirror_cookies(set_cookies, site_tag(target))
        if mirrored:
            extra["Set-Cookie"] = mirrored

        if code in (301, 302, 303, 307, 308):
            loc = rheaders.get("Location", "")
            extra["Location"] = prox(urljoin(target, loc))
            return self.send_bytes(code, b"", extra=extra)

        ctype = rheaders.get("Content-Type", "application/octet-stream")
        low = ctype.lower()
        charset = "utf-8"
        m = re.search(r"charset=([\w-]+)", low)
        if m:
            charset = m.group(1)

        if (method != "GET" and "json" in low
                and re.search(r"login|passport|auth|sign_?in|verify|captcha|token", target, re.I)):
            print(f"   [auth] {method} {urlparse(target).netloc} -> HTTP {code} (response body hidden)")

        if "text/html" in low:
            data = rewrite_html(data.decode(charset, "replace"), target).encode("utf-8")
            ctype = "text/html; charset=utf-8"
        elif "text/css" in low:
            data = rewrite_css(data.decode(charset, "replace"), target).encode("utf-8")
            ctype = "text/css; charset=utf-8"

        for name in _PASS_RESP:
            if rheaders.get(name):
                extra[name] = rheaders[name]

        if (parsed.path == "/go" and "text/html" in low
                and self.headers.get("Sec-Fetch-Dest", "document") == "document"):
            # Remember the last real page, so script requests can find their site.
            keep = quote(target, safe="")
            if len(keep) > 1500:   # a cookie that's too big is silently dropped
                t = urlparse(target)
                keep = quote(f"{t.scheme}://{t.netloc}/", safe="")
            extra.setdefault("Set-Cookie", []).append(
                f"__pxbase={keep}; Path=/; SameSite=Lax")
        if method == "GET" and code == 200 and is_static(low) and len(data) < 5_000_000:
            if len(cache) > 400:
                cache.clear()
            cache[target] = (time.time(), code, ctype, data)
            extra["Cache-Control"] = f"max-age={CACHE_SECONDS}"
        self.send_bytes(code, data, ctype, extra)


if __name__ == "__main__":
    print(f"DeeProxy v{VERSION} listening on {HOST}:{PORT} (public visitor access)")
    print("   Standard HTTPS transport; no browser-fingerprint or anti-bot bypass is enabled.")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()
