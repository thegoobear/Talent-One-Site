#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 23 17:16:44 2017

Makes a list of Movie objects and passes fresh_tomatoes to create a page

@author: Tripp
"""

from flask import Flask, render_template, flash, request, abort, session as login_session, redirect, url_for, jsonify, send_from_directory
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Actor, Photo, Credit, User
from PIL import Image
import random, string
import os
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///talentone.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()

app = Flask(__name__)

@app.route('/')
@app.route('/index')
def homepage():
     
    rowCount = int(session.query(Photo).filter(Photo.path != 'nophoto.jpg').count())
    
    number_of_pics = 3
    
    bannerpics = bannerpicfill(number_of_pics, rowCount)
    
    bannerpics = removeBadPics(bannerpics, rowCount, number_of_pics)
    

    if 'username' in login_session:
        user = session.query(User).filter_by(username = login_session['username']).first()
        return render_template("index.html", piclist = bannerpics, user = user)
    else:
        return render_template("index.html", piclist = bannerpics, user = None)
    
def removeBadPics(bannerpics, rowCount, number_of_pics):
    
    if number_of_pics > rowCount:
        
        for idx, pic in enumerate(bannerpics):
            
            im = Image.open("static/img/" + pic.path)
            picsize = im.size
            
            if (picsize[0]>picsize[1]):
                del bannerpics[idx]
    
    for idx, pic in enumerate(bannerpics):
        
        while True:
            im = Image.open("static/img/" + pic.path)
            picsize = im.size
            
            if (picsize[0] > picsize[1] or bannerpics.count(pic)>1):
                temppic = session.query(Photo).filter(Photo.path != 'nophoto.jpg', Photo.path != pic.path).offset(int(rowCount*random.random())).first()
                if temppic and temppic not in bannerpics:
                    bannerpics[idx]=temppic
                    pic = bannerpics[idx]
                    im.close()
            else:
                im.close()
                break
    
    return bannerpics

def bannerpicfill(count, rowCount):
    
    bannerpics=[]
    
    if count > rowCount:
        
        temppic = session.query(Photo).filter(Photo.path != 'nophoto.jpg').all()

        return temppic
    
    for x in range(0,count):
        
        
        temppic = session.query(Photo).filter(Photo.path != 'nophoto.jpg').offset(int(rowCount*random.random())).first()
    
        if temppic not in bannerpics:
            bannerpics.append(temppic)
        else:
            x-=1
            
            
    return bannerpics
    
@app.route('/about')
def aboutpage():
    rowCount = int(session.query(Photo).count())
    bannerpics = session.query(Photo).offset(int(rowCount*random.random())).limit(6).all()
    return render_template("index.html", piclist = bannerpics)
    
@app.route('/contact')
def contactpage():
    return "Contact"
    
@app.route('/credits')
def creditspage():
    rowCount = int(session.query(Photo).count())
    bannerpics = session.query(Photo).offset(int(rowCount*random.random())).limit(6).all()
    return render_template("index.html", piclist = bannerpics)
    
@app.route('/login', methods = ['GET', 'POST'])
def loginpage():
    
    if request.method == 'GET':
        
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        login_session['state'] = state
    
        return render_template("login.html", STATE = state)
    
    if request.method == 'POST':
        
        email = request.form['email']
        password = request.form['password']
        dbuser = session.query(User).filter_by(email = email).first()
          
        if dbuser:
            if dbuser.verify_password(password):
                login_session['username'] = dbuser.username
                login_session['id'] = dbuser.id
                login_session['email']=dbuser.email
                return homepage()
            

@app.route('/login/newuser', methods = ['POST'])
def newuser():
    
    state = request.form['STATE']
    
    newuser = User(username = request.form['username'], email = request.form['email'])
    newactor = Actor(user = newuser)
    newphoto = Photo(user = newuser, path="nophoto.jpg")
    newcredit = Credit(user = newuser)
    newuser.hash_password(request.form['password'])
    
    if session.query(User).filter_by(username = newuser.username).first() is not None:
        abort(400)
        
    if login_session['state'] != state:
        abort(400)
        
    session.add(newuser)
    session.add(newactor)
    session.add(newphoto)
    session.add(newcredit)
    session.commit()
    
    return homepage()

@app.route('/fbconnect', methods = ['POST'])
def fbconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Obtain authorization code
    code = request.data
    
    print(code)
    
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    
    url = "https://graph.facebook.com/v2.10/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s" % (app_id ,app_secret, code)
    
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
   
    token = result['access_token']
    
    url = "https://graph.facebook.com/v2.10/me?access_token=%s&fields=id,name,picture,email" % token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    
    login_session['username'] = result['name']
    login_session['picture'] = result['picture']['data']['url']
    login_session['email'] = result['email']
    login_session['provider'] = 'facebook'
    login_session['id'] = result['id']
    
    newuser = User(username = login_session['username'], email = login_session['email'], id = int(result['id']))
    newactor = Actor(user = newuser)
    newphoto = Photo(user = newuser, path="nophoto.jpg")
    newcredit = Credit(user = newuser)
    #newuser.hash_password('id')
    
    if session.query(User).filter_by(username = newuser.username).first() is None:
        
        session.add(newuser)
        session.add(newactor)
        session.add(newphoto)
        session.add(newcredit)
        session.commit()

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/gconnect', methods = ['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['provider'] = 'google'
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    
    newuser = User(username = login_session['username'], email = login_session['email'], id = int(data['id']))
    newactor = Actor(user = newuser)
    newphoto = Photo(user = newuser, path="nophoto.jpg")
    newcredit = Credit(user = newuser)
    #newuser.hash_password('id')
    
    if session.query(User).filter_by(username = newuser.username).first() is None:
        
        session.add(newuser)
        session.add(newactor)
        session.add(newphoto)
        session.add(newcredit)
        session.commit()

    output = '<br>'
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output

@app.route('/gdisconnect')
def gdisconnect():
 
    provider = login_session.get('provider')
    
    if provider is None:
      
        login_session.clear()
        
            
        resp = make_response(redirect(url_for('homepage')))
        
        #Fixes error in Safari caused by pre-fetch of cached pages
        resp.headers['Cache-Control']='no-cache, no-store, must-revalidate, post-check=0, pre-check=0'
        
        return resp

    if provider == 'google':
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
    
        if result['status'] == '200':
                    
            login_session.clear()
        
        
            resp = make_response(redirect(url_for('homepage')))
        
            #Fixes error in Safari caused by pre-fetch of cached pages
            resp.headers['Cache-Control']='no-cache, no-store, must-revalidate, post-check=0, pre-check=0'
        
            return resp
    
        else:
        
            response = make_response(json.dumps('Failed to revoke token for given user.', 400))
            response.headers['Content-Type'] = 'application/json'
            return response
        
    if provider == 'facebook':
        
        login_session.clear()
        
        resp = make_response(redirect(url_for('homepage')))
        
        #Fixes error in Safari caused by pre-fetch of cached pages
        resp.headers['Cache-Control']='no-cache, no-store, must-revalidate, post-check=0, pre-check=0'
        
        return resp

    
@app.route('/talent')
def talentpage():
    return "talent"
    
@app.route('/talent/profile/<int:profile_id>')
def profilepage(profile_id):
    
    actor = session.query(Actor).filter_by(user_id=profile_id).first()
    photo = session.query(Photo).filter_by(user_id=profile_id).first()
    credit = session.query(Credit).filter_by(user_id=profile_id).first()
    user = session.query(User).filter_by(id=profile_id).first()
    
    if 'id' in login_session:
        if login_session['id'] == profile_id:
    
            return render_template("profile.html", actor=actor, photo=photo, credit=credit, user=user)
    
    return render_template("profile.html", actor=actor, photo=photo, credit=credit)
    
    
@app.route('/talent/profile/<int:profile_id>/delete')
def deleteprofilepage():
    return "delete profile"
    
@app.route('/account/<int:profile_id>')
def accountpage():
    return "account"
    
@app.route('/admin')
def adminpage():
    return "admin"
    
@app.route('/admin/add')
def addprofilepage():
    return "add profile"
    
@app.route('/submissions')
def submissionpage():
    return "submissions"
    
@app.route('/upload')
def uploadphoto():
    return "index.html"
    
if __name__=='__main__':
    app.debug = True
    app.secret_key = os.urandom(24)
    app.run(host = '0.0.0.0', port = 5000)