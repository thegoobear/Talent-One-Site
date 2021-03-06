#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 22 17:53:32 2017

@author: Tripp
"""

import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
from sqlalchemy.types import Boolean
from passlib.apps import custom_app_context as pw_context

Base = declarative_base()

class User(Base):
    
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    #username = Column(String(80), nullable=False, index = True)
    password = Column(String(80))
    email = Column(String(80), nullable=False, index=True)
    phone = Column(Integer)
    address1 = Column(String(80))
    address2 = Column(String(80))
    city = Column(String(80))
    state = Column(String(2))
    zipcode = Column(Integer)
    paid = Column(Boolean)
    featured = Column(Boolean)
    admin = Column(Boolean)
    
    def hash_password (self, password):
        self.password = pw_context.encrypt(password)
    
    def verify_password (self, password):
        return pw_context.verify(password, self.password)
    
    @property
    def serialize(self):
        return {
                'username':self.username,
                'email':self.email
                }

class Actor(Base):
    
    __tablename__ = 'actor'
    
    id = Column(Integer, primary_key=True)
    firstname = Column(String(250))
    lastname = Column(String(250))
    height_feet = Column(Integer)
    height_inches = Column(Integer)
    age = Column(Integer)
    sag = Column(Boolean)
    equity = Column(Boolean)
    gender = Column(String(20))
    hair = Column(String(20))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref=backref("actor", cascade="all,delete"))
    
    @property
    def serialize(self):
        return {
                'name':self.username,
                'height':self.height_feet + "\'" + self.height_inches + "\"",
                'sag':self.sag,
                'gender':self.gender,
                'hair':self.hair
                }
    
class Photo(Base):
    
    __tablename__ = 'photo'
    
    path = Column(String(80), nullable=False)    
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    actor_id = Column(Integer, ForeignKey('actor.id'))
    actor = relationship(Actor)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref=backref("photo", cascade="all,delete")) 
    
class Credit(Base):
    
    __tablename__ = 'credit'
    
    production = Column(String(80))
    id = Column(Integer, primary_key=True)
    company = Column(String(80))
    role = Column(String(40))
    director = Column(String(80))
    actor_id = Column(Integer, ForeignKey('actor.id'))
    actor = relationship(Actor, backref=backref("credit", cascade="all,delete"))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref=backref("credit", cascade="all,delete")) 
    
        
engine = create_engine('sqlite:///talentone.db')
Base.metadata.create_all(engine)