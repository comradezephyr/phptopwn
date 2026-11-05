"""Static HTML templates for the emulated Apache/PHP surface."""
from __future__ import annotations

import html as html_module
from typing import Any

from .config import DecoyConfig


def _quote(value: Any) -> str:
    return html_module.escape(str(value))


def php_fatal_page(cfg: DecoyConfig) -> str:
    return f"""<!DOCTYPE html>
<html><head><title>500 Internal Server Error</title></head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p>
<hr>
<address>{_quote(cfg.server_token)} Server</address>
</body></html>
"""


TIMEOUT_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>408 Request Timeout</title>
</head><body>
<h1>Request Timeout</h1>
<p>Server timeout waiting for the HTTP request from the client.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""

FORBIDDEN_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""

BAD_HEADER_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Size of a request header field exceeds server limit.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def index_page(cfg: DecoyConfig, port: int) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Acme Intranet &mdash; File Portal</title></head>
<body>
<h1>Acme Intranet File Portal</h1>
<p>Internal document exchange. Authorised users only.</p>
<form action="/upload.php" method="post" enctype="multipart/form-data">
  <label>Select file: <input type="file" name="file"></label>
  <input type="submit" value="Upload file">
</form>
<p>Server: {_quote(cfg.server_token)} &middot; PHP {_quote(cfg.php_version)}</p>
<ul>
  <li><a href="/uploads/">Uploaded files</a></li>
  <li><a href="/phpinfo.php">System information</a></li>
</ul>
<hr>
<address>{_quote(cfg.server_token)} Server at {_quote(cfg.server_name)} Port {port}</address>
</body></html>
"""


def phpinfo_page(cfg: DecoyConfig) -> str:
    rows = {
        "PHP Version": cfg.php_version,
        "System": "Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64",
        "Server API": "FPM/FastCGI",
        "Loaded Configuration File": "/etc/php/8.1/fpm/php.ini",
        "memory_limit": cfg.memory_limit,
        "post_max_size": "128M",
        "upload_max_filesize": "128M",
        "max_file_uploads": "20",
        "max_input_vars": "1000",
        "session.upload_progress.enabled": "On",
        "session.upload_progress.cleanup": "On",
        "session.upload_progress.prefix": "upload_progress_",
        "session.save_path": "/var/lib/php/sessions",
        "allow_url_include": "Off",
        "disable_functions": "exec,passthru,shell_exec,system",
    }
    body = "\n".join(
        f'<tr><td class="e">{_quote(key)}</td><td class="v">{_quote(value)}</td></tr>'
        for key, value in rows.items()
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>phpinfo()</title></head>
<body>
<h1>PHP Version {_quote(cfg.php_version)}</h1>
<table>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
{body}
</table>
<hr>
<address>{_quote(cfg.server_token)} Server at {_quote(cfg.server_name)}</address>
</body></html>
"""


UPLOADS_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Index of /uploads</title></head>
<body>
<h1>Index of /uploads</h1>
<pre>
<a href="../">../</a>
<a href="quarterly-report.pdf">quarterly-report.pdf</a>        2026-09-14 09:21   412K
<a href="backup-2026-09.tar.gz">backup-2026-09.tar.gz</a>        2026-09-30 23:02   8.4M
<a href="onboarding.docx">onboarding.docx</a>              2026-10-02 11:47   184K
<a href="logo.png">logo.png</a>                     2026-08-19 15:33    27K
</pre>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""

SERVER_STATUS_PAGE = """<!DOCTYPE html>
<html><head><title>Apache Server Status</title></head>
<body>
<h1>Apache Server Status for localhost</h1>
<dl>
<dt>Server Version: {server_token} OpenSSL/3.0.2</dt>
<dt>Server MPM: event</dt>
<dt>Server Built: 2024-01-24T14:22:01</dt>
<dt>Current Time: __TIME__</dt>
<dt>Restart Time: __TIME__</dt>
<dt>Parent Server Config. Generation: 3</dt>
<dt>Total accesses: 18422 - Total Traffic: 91.4 MB</dt>
<dt>2 requests currently being processed, 6 idle workers</dt>
</dl>
<pre>__SCOREBOARD__</pre>
</body></html>
"""

WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; Acme &mdash; WordPress</title></head>
<body class="login">
<div id="login"><h1><a href="/">Acme</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body></html>
"""

LOGIN_FAILED_PAGE = """<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; Acme &mdash; WordPress</title></head>
<body class="login">
<div id="login"><h1><a href="/">Acme</a></h1>
<div id="login_error"><strong>Error:</strong> The password you entered for the username is incorrect.</div>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form>
</div>
</body></html>
"""

SESSION_UPLOAD_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Upload complete</title></head>
<body>
<p>Upload completed successfully.</p>
<!-- session.upload_progress: request handled by upload progress callback -->
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def upload_success_page(filename: str) -> str:
    safe = html_module.escape(filename) if filename else "unnamed"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Upload complete</title></head>
<body>
<h1>Upload complete</h1>
<p>The file <strong>{safe}</strong> has been uploaded to <code>/uploads/</code>.</p>
<p><a href="/uploads/">Return to uploads</a></p>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def oom_page(cfg: DecoyConfig) -> str:
    limit_bytes = _memory_limit_bytes(cfg.memory_limit)
    return f"""<br />
<b>Fatal error</b>:  Allowed memory size of {limit_bytes} bytes exhausted (tried to allocate 40960 bytes) in <b>/var/www/html/upload.php</b> on line <b>17</b><br />
<br />
<b>Fatal error</b>:  Uncaught Error: Allowed memory size exhausted while parsing multipart body in /var/www/html/upload.php:21
Stack trace:
#0 {{main}}
  thrown in <b>/var/www/html/upload.php</b> on line <b>21</b><br />
<address>{_quote(cfg.server_token)} Server at {_quote(cfg.server_name)} Port 80</address>
"""


def not_found_page(cfg: DecoyConfig, path: str) -> str:
    return f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL {_quote(path[:300])} was not found on this server.</p>
<hr>
<address>{_quote(cfg.server_token)} Server at {_quote(cfg.server_name)} Port 80</address>
</body></html>
"""


def method_not_allowed_page(method: str) -> str:
    return f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>405 Method Not Allowed</title>
</head><body>
<h1>Method Not Allowed</h1>
<p>The requested method {_quote(method[:32])} is not allowed for this URL.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def _memory_limit_bytes(value: str) -> int:
    text = value.strip().upper()
    multiplier = 1
    if text.endswith("K"):
        multiplier, text = 1024, text[:-1]
    elif text.endswith("M"):
        multiplier, text = 1024 * 1024, text[:-1]
    elif text.endswith("G"):
        multiplier, text = 1024 * 1024 * 1024, text[:-1]
    try:
        return int(float(text) * multiplier)
    except ValueError:
        return 134217728
