#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 25 21:33:06 2017

@author: Tripp
"""

from flask_wtf import FlaskForm
from wtforms import TextField, TextAreaField, SubmitField, validators, \
IntegerField, RadioField, PasswordField, BooleanField, SelectField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_uploads import UploadSet, IMAGES
from database_setup import User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base

photos = UploadSet('photos', IMAGES)
resume = UploadSet('resume', ('pdf'))

STATE_ABBREV = ['AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA', 
                'HI', 'ID', 'IL', 'IN', 'IO', 'KS', 'KY', 'LA', 'ME', 'MD', 
                'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 
                'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 
                'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY']

engine = create_engine('sqlite:///talentone.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()

def Unique(form, field):
        
    message = 'Email already in use'
        
    if session.query(User).filter_by(email=field.data).first():
        
        raise validators.ValidationError(message)

class ContactForm(FlaskForm):
    name = TextField('Name', [validators.DataRequired('Please enter your name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    message = TextAreaField('Message', [validators.DataRequired('Please enter a message')])
    submit = SubmitField('Send')
    
class RegisterForm(FlaskForm):
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email'), Unique])
    password = PasswordField('Password', [validators.DataRequired('Please enter a password'), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    access = TextField('Access Code', [validators.DataRequired('Valid access code required')])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    password = PasswordField('Password', [validators.DataRequired('Please enter a password')])
    submit = SubmitField('Submit')
    
class EditUser(FlaskForm):
    firstname = TextField('First Name', [validators.DataRequired('Please enter your first name')])
    lastname = TextField('Last Name', [validators.DataRequired('Please enter your last name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    age = IntegerField('Age', [validators.DataRequired('Please enter your age')], render_kw={'maxlength':2})
    height_feet = IntegerField('\'', render_kw={'maxlength':1})
    height_inches = IntegerField('"', render_kw={'maxlength':2})
    hair = SelectField('Hair', choices=[('Blonde', 'Blonde'), ('Brunette', 'Brunette'), ('Black', 'Black'), ('Red', 'Red'), ('Grey', 'Grey')])
    sag = BooleanField('SAG/AFTRA')
    equity = BooleanField('Actor\'s Equity')
    phone = TextField(label='Phone', render_kw={'maxlength':12}, validators=[validators.Length(min=10, max=13)])
    photo = FileField('Headshot', [FileAllowed(photos, 'Headshots can only be image files')])
    #creditprod = TextField('Production', [validators.DataRequired('Enter production name')])
    #creditrole = TextField('Role', [validators.DataRequired('Enter role')])
    #creditcompany = TextField('Company', [validators.DataRequired('Enter production company name')])
    address1 = TextField(label='Address Line 1')
    address2 = TextField(label='Address Line 2')
    city = TextField(label='City')
    state = SelectField('State', choices=[(state, state) for state in STATE_ABBREV])
    zipcode = IntegerField('Zip', render_kw={'maxlength':5})
    submit = SubmitField('Save')

class SubmissionForm(FlaskForm):
    name = TextField('Name', [validators.DataRequired('Please enter your name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    phone = TextField(label='Phone', render_kw={'maxlength':12}, validators=[validators.Length(min=10, max=13)])
    message = TextAreaField('Cover Letter', [validators.DataRequired('Please enter a message')])
    photo = FileField('Headshot', [FileRequired('Please upload a headshot'), FileAllowed(photos, 'Headshots can only be image files')])
    resume = FileField('Resume', [FileRequired('Please upload a resume'), FileAllowed(resume, 'Resume can only be PDF')])
    submit = SubmitField('Submit')
    