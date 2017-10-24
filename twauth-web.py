import os
from flask import Flask, render_template, request, url_for
from requests_oauthlib import OAuth1Session
import oauth2
import urllib.parse
import json

app = Flask(__name__)

app.debug = False

request_token_url = 'https://twitter.com/oauth/request_token'
access_token_url = 'https://twitter.com/oauth/access_token'
#authorize_url = 'https://twitter.com/oauth/authorize'
authorize_url = 'https://twitter.com/oauth/authenticate'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'

# Support keys from environment vars (heroku). You should add your keys to config.cfg
#app.config['APP_CONSUMER_KEY'] = os.getenv('TWAUTH_APP_CONSUMER_KEY', 'API_Key_from_Twitter')
#app.config['APP_CONSUMER_SECRET'] = os.getenv('TWAUTH_APP_CONSUMER_SECRET', 'API_Secret_from_Twitter')

# config.cfg should look like:
# APP_CONSUMER_KEY = 'API_Key_from_Twitter'
# APP_CONSUMER_SECRET = 'API_Secret_from_Twitter'
app.config.from_pyfile('config.cfg')

oauth_store = {}

@app.route('/')
def hello():
    return render_template('index.html')

@app.route('/start')
def start():
    # Generate the OAuth request tokens, then display them
    app_callback_url = url_for('callback', _external=True)

    # Using OAuth1Session
    oauth = OAuth1Session(
        app.config['APP_CONSUMER_KEY'],
        app.config['APP_CONSUMER_SECRET'])
    fetch_response = oauth.fetch_request_token(request_token_url)

    resource_owner_key = fetch_response.get('oauth_token')
    resource_owner_secret = fetch_response.get('oauth_token_secret')

    print(resource_owner_key)
    print(resource_owner_secret)

    consumer = oauth2.Consumer(app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    client = oauth2.Client(consumer)
    print(urllib.parse.urlencode({"oauth_callback": app_callback_url}))
    resp, content = client.request(request_token_url, "POST", body=urllib.parse.urlencode({"oauth_callback": app_callback_url}))
    #resp, content = client.request(request_token_url, "POST",
    #                               body=urllib.parse.urlencode({"oauth_callback": 'oob'}))
    if resp['status'] != '200':
        error_message = "Invalid response %s" % resp['status']
        return render_template('error.html', error_message=error_message)

    oauth_token = fetch_response.get('oauth_token')
    oauth_token_secret = fetch_response.get('oauth_token_secret')

    oauth_store[oauth_token] = oauth_token_secret
    return render_template('start.html', authorize_url=authorize_url, oauth_token=oauth_token, request_token_url=request_token_url)

@app.route('/callback')
def callback():
    # Accept the callback params, get the token and call the API to display this user's name and handle
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    oauth_denied = request.args.get('denied')
    # if the oauth request was denied, delete our local token and show an error message
    if oauth_denied:
        if oauth_denied in oauth_store:
            del oauth_store[oauth_denied]
        return render_template('error.html', error_message="the OAuth request was denied by this user")

    if not oauth_token or not oauth_verifier:
        return render_template('error.html', error_message="callback param(s) missing")

    # unless oauth_token is still stored locally, return error
    if oauth_token not in oauth_store:
        return render_template('error.html', error_message="oauth_token not found locally")

    oauth_token_secret = oauth_store[oauth_token]

    # if we got this far, we have both call back params and we have found this token locally
    # Using OAuth1Session
    print(oauth_verifier)
    oauth = OAuth1Session(
        app.config['APP_CONSUMER_KEY'],
        app.config['APP_CONSUMER_SECRET'],
        oauth_token,
        oauth_token_secret,
        verifier=oauth_verifier)
    fetch_access = oauth.fetch_access_token(access_token_url)

    print(fetch_access)
    #screen_name = access_token['screen_name']
    #user_id = access_token['user_id']

    # These are the tokens you would store long term, someplace safe
    real_oauth_token = fetch_access['oauth_token']
    real_oauth_token_secret = fetch_access['oauth_token_secret']

    consumer = oauth2.Consumer(app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    token = oauth2.Token(oauth_token, oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth2.Client(consumer)

    screen_name = fetch_access['screen_name']
    user_id = fetch_access['user_id']
    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    real_token = oauth2.Token(real_oauth_token, real_oauth_token_secret)
    real_client = oauth2.Client(consumer, real_token)
    real_resp, real_content = real_client.request(show_user_url + '?user_id=' + user_id, "GET")

    if real_resp['status'] != '200':
         error_message = "Invalid response from Twitter API GET users/show : %s" % real_resp['status']
         return render_template('error.html', error_message=error_message)

    response = json.loads(real_content)

    friends_count = response['friends_count']
    statuses_count = response['statuses_count']
    followers_count = response['followers_count']
    name = response['name']

    # don't keep this token and secret in memory any longer
    del oauth_store[oauth_token]

    return render_template('callback-success.html', screen_name=screen_name, user_id=user_id, name=name,
        friends_count=friends_count, statuses_count=statuses_count, followers_count=followers_count, access_token_url=access_token_url)
    #return render_template('callback-success.html', screen_name='blank', user_id='blank', name='Sprinkles',
    #    friends_count=10, statuses_count=2, followers_count=923, access_token_url=access_token_url)

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message='uncaught exception'), 500

if __name__ == '__main__':
    app.run()
