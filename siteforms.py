#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 25 21:33:06 2017

@author: Tripp
"""

from flask_wtf import FlaskForm
from wtforms import TextField, TextAreaField, SubmitField, validators, IntegerField, RadioField, PasswordField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_uploads import UploadSet, IMAGES

photos = UploadSet('photos', IMAGES)
resume = UploadSet('resume', ('pdf'))

class ContactForm(FlaskForm):
    name = TextField('Name', [validators.DataRequired('Please enter your name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    message = TextAreaField('Message', [validators.DataRequired('Please enter a message')])
    submit = SubmitField('Send')
    
class RegisterForm(FlaskForm):
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    password = PasswordField('Password', [validators.DataRequired('Please enter a password'), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    
class LoginForm(FlaskForm):
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    password = PasswordField('Password', [validators.DataRequired('Please enter a password')])

    
class EditUser(FlaskForm):
    firstname = TextField('First Name', [validators.DataRequired('Please enter your first name')])
    lastname = TextField('Last Name', [validators.DataRequired('Please enter your last name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    age = TextField('Age', [validators.DataRequired('Please enter your age')])
    height = IntegerField('Height')
    sag = RadioField('SAG/AFTRA', choices=[(True, 'Yes'), (False, 'No')])
    phone = TextField(label='Phone', render_kw={'maxlength':12}, validators=[validators.Length(min=10, max=13)])
    photo = FileField('Headshot', [FileRequired('Please upload a headshot'), FileAllowed(photos, 'Headshots can only be image files')])
    creditprod = TextField('Production', [validators.DataRequired('Enter production name')])
    creditrole = TextField('Role', [validators.DataRequired('Enter role')])
    creditcompany = TextField('Company', [validators.DataRequired('Enter production company name')])
    submit = SubmitField('Submit')

class SubmissionForm(FlaskForm):
    name = TextField('Name', [validators.DataRequired('Please enter your name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    phone = TextField(label='Phone', render_kw={'maxlength':12}, validators=[validators.Length(min=10, max=13)])
    message = TextAreaField('Cover Letter', [validators.DataRequired('Please enter a message')])
    photo = FileField('Headshot', [FileRequired('Please upload a headshot'), FileAllowed(photos, 'Headshots can only be image files')])
    resume = FileField('Resume', [FileRequired('Please upload a resume'), FileAllowed(resume, 'Resume can only be PDF')])
    submit = SubmitField('Submit')
    