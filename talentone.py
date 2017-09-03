#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 23 17:16:44 2017

Makes a list of Movie objects and passes fresh_tomatoes to create a page

@author: Tripp
"""

from flask import Flask, render_template, request, abort, session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Actor, Photo, Credit, User
from PIL import Image
import random
import os


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
        login_session['id'] = user.id
        return render_template("index.html", piclist = bannerpics, user = user)
    else:
        return render_template("index.html", piclist = bannerpics)
    
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
        print(temppic)
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
    
    #tests=session.query(User).all()
    
    #for item in tests:
    #    print (item.username)
    
    
    if request.method == 'GET':
    
        return render_template("login.html")
    
    if request.method == 'POST':
        
        user = request.form['username']
        password = request.form['password']
        dbuser = session.query(User).filter_by(username = user).first()
          
        if dbuser:
            if dbuser.verify_password(password):
                login_session['username'] = dbuser.username
                return homepage()

@app.route('/login/newuser', methods = ['POST'])
def newuser():
    
    newuser = User(username = request.form['username'], email = request.form['email'])
    newactor = Actor(user = newuser)
    newphoto = Photo(user = newuser, path="nophoto.jpg")
    newcredit = Credit(user = newuser)
    newuser.hash_password(request.form['password'])
    
    if session.query(User).filter_by(username = newuser.username).first() is not None:
        abort(400)
        
    session.add(newuser)
    session.add(newactor)
    session.add(newphoto)
    session.add(newcredit)
    session.commit()
    
    return homepage()

    
@app.route('/talent')
def talentpage():
    return "talent"
    
@app.route('/talent/profile/<int:profile_id>')
def profilepage(profile_id):
    
    actor = session.query(Actor).filter_by(user_id=profile_id).first()
    photo = session.query(Photo).filter_by(user_id=profile_id).first()
    credit = session.query(Credit).filter_by(user_id=profile_id).first()
    
    return render_template("profile.html", actor=actor, photo=photo, credit=credit)
    
@app.route('/talent/profile/<int:profile_id>/edit')
def editprofilepage():
    return "edit profile"
    
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