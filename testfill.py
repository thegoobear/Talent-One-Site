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

    Rusty = Photo(path='rusty.jpg')
    Shannon = Photo(path='shannon.jpg')
    session.add(Rusty)
    session.add(Shannon)
    session.commit()