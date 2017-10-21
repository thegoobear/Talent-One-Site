#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Latest Revision 9/15/17

A web page/app for a talent agency allowing clients to manage profiles

@author: Tripp
"""

from flask import Flask, render_template, flash, request, abort, session as login_session, redirect, url_for, jsonify, send_from_directory
from flask_uploads import UploadSet, IMAGES, configure_uploads, patch_request_class
#from siteforms import ContactForm
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
from os import walk
from siteforms import ContactForm
from flask_mail import Mail, Message

#Pull in the client secret key for Google Sign In
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

#Connect to SQL database
engine = create_engine('sqlite:///talentone.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()

app = Flask(__name__)

#Set the destination for user photo uploads
app.config['UPLOADED_PHOTOS_DEST'] = 'static/img'
app.config['MAIL_DEFAULT_SENDER'] = 'contact@talentoneagency.com'
app.config['MAIL_SUPPRESS_SEND'] = True

photos = UploadSet('photos', IMAGES)
configure_uploads(app, (photos))
patch_request_class(app)
mail = Mail(app)

@app.route('/')
@app.route('/index')
def homepage():
    
    #Get the number of photos that aren't placeholders
    rowCount = int(session.query(Photo).filter(Photo.path != 'nophoto.jpg').count())
    
    #The number of photos to display in the homepage banner
    number_of_pics = 3
    
    #Populate the list of pictures to display
    bannerpics = bannerpicfill(number_of_pics, rowCount)
    
    #Removes duplicates and photos in landscape orientation
    bannerpics = removeBadPics(bannerpics, rowCount, number_of_pics)


    if 'email' in login_session:
        user = session.query(User).filter_by(email = login_session['email']).first()
        return render_template("index.html", piclist = bannerpics, user = user)
    else:
        return render_template("index.html", piclist = bannerpics, user = None)

def removeBadPics(bannerpics, rowCount, number_of_pics):
    
    bannerpics2 = []

    #If the number of photos in the database is less than or equal to the
    #number needed for display, just remove landscape photos
    if number_of_pics >= rowCount:

        for idx, pic in enumerate(bannerpics):

            im = Image.open("static/img/uploads/" + pic.path)
            picsize = im.size

            if (picsize[0]<picsize[1]):
                bannerpics2.append(bannerpics[idx])
                
            im.close()
    
        return bannerpics2
    
    #If there are more photos in the DB than will be displayed, we must
    #replace duplicates as well as remove landscape photos. This for loop
    #provides an index for the current iteration's photo
    for idx, pic in enumerate(bannerpics):

        #Replace the photo until there are no duplicates
        while True:
            
            im = Image.open("static/img/uploads/" + pic.path)
            picsize = im.size
            
            #If width is greater than height or a duplicate is present in the
            #list
            if (picsize[0] > picsize[1] or bannerpics.count(pic)>1):
                #print(pic.path)
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

    #If the number of available photos is less than or equal to the number
    #for display, simply populate list will all of them after randomizing
    #print(count, rowCount)
    if count >= rowCount:

        temppic = session.query(Photo).filter(Photo.path != 'nophoto.jpg').all()

        random.shuffle(temppic)
        #print('poo')
        return temppic
    
    #If there are more photos in the DB than will be displayed, pick photos
    #randomly to populate the list. Do not count loops storing duplicates
    x=0
    
    while x < count:

        temppic = session.query(Photo).filter(Photo.path != 'nophoto.jpg').offset(int(rowCount*random.random())).first()

    #Only add photo to list if there is no duplicate
        if temppic not in bannerpics:
            bannerpics.append(temppic)
            x+= 1
        
    return bannerpics

@app.route('/about')
def aboutpage():

    return render_template("about.html")

@app.route('/contact', methods = ['GET', 'POST'])
def contactpage():
    
    form = ContactForm()
    
    if request.method == 'POST' and form.validate():
        
        msg = Message('Talent One Website Contact Form', recipients=['anne@talentoneagency.com'])
        
        msg.body = """
        From: %s <%s>
        %s
        """ % (form.name.data, form.email.data, form.message.data)
        
        mail.send(msg)
        
        if 'id' in login_session:        
            user = session.query(User).filter_by(id=login_session['id']).first()          
            return render_template('contact.html', success=True, user=user)
        
        return render_template('contact.html', success=True)
    
    if 'id' in login_session:        
        user = session.query(User).filter_by(id=login_session['id']).first()
        return render_template('contact.html', form=form, user=user)
    
    return render_template('contact.html', form=form)

@app.route('/credits')
def creditspage():

    posters = []

    for (dirpath, dirnames, filenames) in walk('static/img/posters'):
        posters.extend(filenames)
        break

    for poster in posters:
        if poster[-3:] != 'jpg':
            print(poster[-3:-1])
            print(poster)
            posters.remove(poster)

    random.shuffle(posters)

    if 'id' in login_session:        
        user = session.query(User).filter_by(id=login_session['id']).first() 
        return render_template("credits.html", posters = posters, user = user)

    return render_template("credits.html", posters = posters)

@app.route('/login', methods = ['GET', 'POST'])
def loginpage():

    if request.method == 'GET':

        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        login_session['state'] = state
                     
        if 'id' in login_session:        
            user = session.query(User).filter_by(id=login_session['id']).first()
            
            return render_template("login.html", STATE = state, user=user)

        return render_template("login.html", STATE = state)

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']
        dbuser = session.query(User).filter_by(email = email).first()

        if dbuser:
            if dbuser.verify_password(password):
                login_session['username'] = dbuser.actor[0].name
                login_session['id'] = dbuser.id
                login_session['email']=dbuser.email
                return homepage()


@app.route('/login/newuser', methods = ['POST'])
def newuser():

    state = request.form['STATE']

    newuser = User(email = request.form['email'])
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

    newuser = User(username = login_session['username'], email = login_session['email'])
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
        
    newuser = session.query(User).filter_by(email = login_session['email']).first()
    
    login_session['id'] = newuser.id

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
    
    piclist = session.query(User).all()
    
    for idx, pic in enumerate (piclist):
        piclist[idx] = pic.photo[0].path
    
    if 'id' in login_session:        
        user = session.query(User).filter_by(id=login_session['id']).first()
        
        return render_template('talent.html', piclist = piclist, user=user)

    return render_template('talent.html', piclist = piclist)

@app.route('/talent/profile/<int:profile_id>')
def profilepage(profile_id):

    user = session.query(User).filter_by(id=profile_id).first()

    if 'id' in login_session:
        if login_session['id'] == profile_id:

            return render_template("profile.html", actor=user.actor[0], photo=user.photo[0], credit=user.credit[0], user=user)

    return render_template("profile.html", actor=user.actor[0], photo=user.photo[0], credit=user.credit[0])


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

@app.route('/upload/<int:userid>', methods = ['POST'])
def uploadphoto(userid):

    if request.method == 'POST' and 'photo' in request.files:

        filename = photos.save(request.files['photo'], folder = 'uploads')
        tempuser = session.query(User).filter_by(id=userid).first()
        oldphoto = session.query(Photo).filter_by(user_id=userid).first()
        newphoto = Photo(path=filename[8::], user=tempuser)

        session.add(newphoto)
        session.delete(oldphoto)
        session.commit()
        
        if os.path.isfile('static/img/uploads/' + oldphoto.path) and oldphoto.path != 'nophoto.jpg':
            os.remove('static/img/uploads/' + oldphoto.path)
            
        print(session.query(Photo).count())
        print(int(session.query(Photo).filter(Photo.path != 'nophoto.jpg').count()))

        flash("Photo Saved")

        return redirect(url_for('profilepage', profile_id=userid))

    return redirect(url_for('profilepage', profile_id=userid))
 
if __name__=='__main__':
    app.debug = True
    app.secret_key = os.urandom(24)
    app.run(host = '0.0.0.0', port = 5000)