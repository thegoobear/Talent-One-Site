#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 25 21:33:06 2017

@author: Tripp
"""

from flask_wtf import FlaskForm
from wtforms import TextField, TextAreaField, SubmitField, validators

class ContactForm(FlaskForm):
    name = TextField('Name', [validators.DataRequired('Please enter your name')])
    email = TextField('Email', [validators.DataRequired('Please enter your email'), validators.Email('Please enter a valid email')])
    message = TextAreaField('Message', [validators.DataRequired('Please enter a message')])
    submit = SubmitField('Send')
  
class NewUser(FlaskForm):
    firstname = TextField('First Name', [validators.DataRequired('Please enter your name')])
    lastname = TextField('Last Name', [validators.DataRequired('Please enter your name')])
    age = TextField('Age', [validators.DataRequired('Please enter your name')])