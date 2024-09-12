#!/usr/bin/env python3
'''
auth
'''
import bcrypt
from user import User
from db import DB
from sqlalchemy.orm.exc import NoResultFound

def _hash_password(password: str) -> bytes:
    '''
    method that takes in a password string arguments and returns bytes.
    The returned bytes is a salted hash of the input password
    '''
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        '''constructor'''
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        '''register new user'''
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))
