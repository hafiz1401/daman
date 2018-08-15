from datetime import datetime
from app import mongo, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5

class User():

    def __init__(self, username=''):
        self.username = username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.username

    @staticmethod
    def validate_login(password_hash, password):
        return check_password_hash(password_hash, password)


@login.user_loader
def load_user(name):
    user = mongo.db.datax
    u = user.find_one({'name': name})
    if not u:
        return None
    return User(u['name'])