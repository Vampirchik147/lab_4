# py_ver == "3.6.9"
import flask

app = flask.Flask(__name__)



import requests
# check internet connection is available
inet_conn = False
if requests.__version__ <= '2.19.1':
    try:
        requests.get('https://google.com')
        inet_conn = True
    except:
        pass


@app.route('/introduction')
def introduction():
    return """
            <html>
                <title>Знакомство</title>
                <body>
                    <form action="/set_name">
                        Представьтесь, пожалуйста: <input name="name" type="text" />
                        <input name="submit" type="submit">
                    </form>
                </body>
            </html>
"""

from flask import escape

@app.route('/')
def index_page():
    if flask.request.cookies.get('name'):
        return """
            <html>
                <title>Приветствие</title>
                <body>
                     <h1>Привет, %s!</h1>
                </body>
            </html>
""" %escape(flask.request.cookies.get('name'))
    else:
        return """
            <html>
                <title>Приветствие</title>
                <script></script>
                <body>
                    <a href="/introduction">Как вас зовут?</a>
                </body>
            </html>
"""


@app.route('/set_name')
def cookie_setter():
    response = flask.make_response(flask.redirect('/'))
    response.set_cookie('name', escape(flask.request.args.get('name')))
    return response


import os, sqlite3
conn = sqlite3.connect("test.db3")
cursor = conn.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS users (
	"id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"name"	TEXT,
	"password"	TEXT
);""")
conn.commit()
users = [('test', 'test'), ('admin', 'password')]
result = cursor.execute("SELECT * FROM users WHERE name = ? AND password = ?;", users[0]).fetchone()
if not result:
    cursor.executemany("INSERT INTO users VALUES(NULL, ?, ?)", users)
    conn.commit()
cursor.close()
conn.close()



def authenticate(name, password):


    sql_statement = "SELECT * FROM users WHERE name = ? AND password = ?;"

    conn = sqlite3.connect("test.db3")
    cursor = conn.cursor()
    result = cursor.execute(sql_statement, (name, password)).fetchone()
    cursor.close()
    conn.close()
    return result


@app.route('/login')
def index_page_html():
    return """
            <html>
                <title>Login page</title>
                <body>
                    <form action="/auth" method="post">
                        Login: <input name="name" type="text"/>
                        Password: <input name="password" type="password" />
                        <input name="submit" type="submit" value="Log in">
                        <input name="redirect_url" value="/?logged_in=1" type="hidden" />
                    </form>
                </body>
            </html>
        """


import hmac
from flask import url_for

@app.route('/auth', methods=["GET", "POST"])
def login_pag():
    name = flask.request.form.get('name')
    password = flask.request.form.get('password')

    if name is None or password is None:
        return """
        <html>
            <body>
                Failed to authenticate
            </body>
        </html>
    """
    hmac_msg = name + password + "SALT_123nwjdnf023"
    hmac_inst = hmac.new("my_super_secure_key".encode('utf8'),
                         msg=hmac_msg.encode('utf8'),
                         digestmod='sha256')
    already_auth = flask.request.cookies.get('ssid') == hmac_inst.hexdigest()
    just_auth = authenticate(name, password)
    if already_auth or just_auth:
        redirect_url = flask.request.args.get('redirect_url', '/')
        if redirect_url:
            response = flask.make_response(flask.redirect(url_for(redirect_url)))
            if just_auth:
                response.set_cookie('ssid', hmac_inst.hexdigest())
            return response

        return """
            <html>
                <body>
                    Successfully logged in
                </body>
            </html>
        """

    return """
        <html>
            <body>
                Failed to authenticate
            </body>
        </html>
    """


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.debug = True
    app.run()
