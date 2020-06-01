import datetime

from flask import render_template, jsonify
from flask_jwt_extended import get_current_user
from werkzeug.security import generate_password_hash, check_password_hash

from application import db, app, jwt
from flask_security import UserMixin, RoleMixin
from marshmallow_sqlalchemy import ModelSchema

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean(), default=False)
    superuser = db.Column(db.Boolean, default=False)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __str__(self):
        return self.email

    def get_id(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def get_password(self, password):
        return check_password_hash(self.password, password)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(email=username).first()

    def encode_auth_token(self, id ):
        try:
            payload = {
                'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=30),
                'iat' : datetime.datetime.utcnow(),
                'sub' :id
            }
            return jwt.encode(payload,
                              app.config.get('SECRET_KEY'),
                              algorithm='HS256'
                              )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    db.create_all()


# flask marshmallow serializer
class UserSchema(ModelSchema):
    class Meta:
        model = User


users_schema = UserSchema(many=True)
user_schema = UserSchema()



