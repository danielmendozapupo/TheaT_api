import json

from flask import Response, jsonify

from application import db, app
from marshmallow_sqlalchemy import ModelSchema


class Movies(db.Model):
    __tablename__ = 'movies'
    movie_id = db.Column(db.Integer, primary_key=True)
    movie_title = db.Column(db.String)
    movie_genre = db.Column(db.Integer, db.ForeignKey('genre.id'), nullable=False)
    movie_director = db.Column(db.String)
    movie_year = db.Column(db.String)
    movie_age = db.Column(db.String)
    genre = db.relationship('Genre', backref=db.backref('movie', lazy=True))

    def __repr__(self):
        return self.movie_title


class Genre(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    genre_name = db.Column(db.String)

    def __repr__(self):
        return self.genre_name


class MovieSchema(ModelSchema):
    class Meta:
        model = Movies
'''     fields = ('movie_id', 'movie_name', ' movie_genre', 'movie_director', 'movie_year')         '''

db.create_all()

movie_schema = MovieSchema()
movies_schema = MovieSchema(many=True)


