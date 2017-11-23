#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 25 22:45:18 2017

@author: Tripp
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Actor, Photo, Credit, User

if __name__=='__main__':
    
    engine = create_engine('sqlite:///talentone.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    
    Rusty = User(email="rusty@poop.com", paid=True, admin = False)
    Rustyactor = Actor(user = Rusty, firstname = 'Rusty')
    Rustypic = Photo(path='rusty.jpg', user = Rusty)
    Shannon = User(email="shannon@poop.com", paid=True, admin = False)
    Shannonactor = Actor(user = Shannon, firstname = 'Shannon')
    Shannonpic = Photo(path='shannon.jpg', user = Shannon)
    Admin = User(email='talentoneagency@gmail.com', admin = True)
    AdminActor = Actor(user=Admin, firstname='Admin')
    Admin.hash_password('goo')
    
    
    session.add(Admin)
    session.add(Rustypic)
    session.add(Rusty)
    session.add(Shannon)
    session.add(Shannonpic)
    session.add(Shannonactor)
    session.commit()