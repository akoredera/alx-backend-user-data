#!/usr/bin/env python3
'''
auth
'''
import bcrypt


def _hash_password(password: str) -> bytes:
    '''
    method that takes in a password string arguments and returns bytes.
    The returned bytes is a salted hash of the input password
    '''
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt)
