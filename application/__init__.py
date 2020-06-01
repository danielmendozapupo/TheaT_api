import sqlite3
from mailbox import Message
import json
from flask import Flask, render_template, session, redirect, url_for, jsonify, request, flash, Response
from flask_mail import Mail
from flask_marshmallow import Marshmallow
from flask_restful import Api
from flask_security import LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required
from flask_login import LoginManager


app = Flask(__name__)

# provides the settings for the application
import common.config

api = Api(app)
ma = Marshmallow(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
loginMng = LoginManager(app)
mail = Mail(app)

import application.movies
import application.admin
import application.accounts


from application import routes


"""
@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    test = application.User.query.filter_by(email=email).first()
    if test:
        return jsonify(message='That email already exists.')
    else:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        user = application.User(first_name=first_name, last_name=last_name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify(message='User created successfully!'), 201

''''
@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        email = request.json['email']
        password = request.json['password']
    else:
        email = request.form['email']
        password = request.form['password']

    test = User.query.filter_by(email=email, password=password).first()
    if test:
        access_token = create_access_token(identity=email)
        return jsonify(message="Login succeeded", access_token=access_token)
    else:
        return jsonify(message='Bad email or password '), 401

'''
@app.route("/login", methods=['GET', 'POST'])
def login():
    if session.get('username'):
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = application.User.objects(email=email).first()
        if user and user.get_password(password):
            flash("{user.first_name}, you are successfully logged in!", "success")
            session['user_id'] = user.user_id
            session['username'] = user.first_name
            return redirect("/index")
        else:
            flash("Sorry, something went wrong.", "danger")
    return render_template("login.html", title="Login", form=form, login=True)


@app.route("/logout")
def logout():
    session['user_id'] = False
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/users', methods=['GET'])
def users():
    users_list = application.User.query.all()
    result = application.users_schema.dump(users_list)
    return jsonify(result)


@app.route('/retrieve_password/<string:email>', methods=['GET'])
def retrieve_password(email: str):
    user = application.User.query.filter_by(email=email).first()
    if user:
        msg = Message('Your Movie Theater password is ' + user.password,
                      sender='admin@theater-api.com',
                      recipients=[email])
        email.send(msg)
        return jsonify(message='Password sent to ' + email)
    else:
        return jsonify(message="That email doesn't exist."), 401


@app.route('/movie_details/<int:movie_id>', methods=['GET'])
def movie_details(movie_id: int):
    movie = application.Movies.query.filter_by(movie_id=movie_id).first()
    if movie:
        result = application.movie_schema.dump(movie)
        return jsonify(result)
    else:
        return jsonify(message="That movie doesn't exist"), 404


@app.route('/add_movie', methods=['POST'])
@jwt_required
def add_movie():
    movie_name = request.form['movie_name']
    test = application.Movies.query.filter_by(movie_name=movie_name).first()
    if test:
        return jsonify(message="There is already a movie by that name"), 409
    else:
        movie_name = request.form['movie name']
        movie_genre = request.form['movie_genre']
        movie_director = request.form['movie_director']
        movie_year = request.form['movie_year']

        new_movie = application.Movies(movie_name=movie_name,
                                       movie_genre=movie_genre,
                                       movie_director=movie_director,
                                       movie_year=movie_year)
        db.session.add(new_movie)
        db.session.commit()
        return jsonify(message='You added a new movie'), 201


@app.route('/update_movie', methods=['PUT'])
@jwt_required
def update_movie():
    movie_id = int(request.form['movie_id'])
    movie = application.Movies.query.filter_by(movie_id=movie_id).first()
    if movie:
        movie.movie_name = request.form['movie_name']
        movie.movie_genre = request.form['movie_genre']
        movie.movie_director = request.form['movie_director']
        movie.movie_year = request.form['movie_year']
        movie.movie_age = request.form['movie_age']
        db.session.commit()
        return jsonify(message="You updated a movie!"), 202
    else:
        return jsonify(message="The movie doesn't exists!"), 404


@app.route('/remove_movie/<int:movie_id>', methods=['DELETE'])
@jwt_required
def remove_movie(movie_id: int):
    movie = application.Movies.query.filter_by(movie_id=movie_id).first()
    if movie:
        db.session.delete(movie)
        db.session.commit()
        return jsonify(message="Movie deleted!"), 202
    else:
        return jsonify(message="The movie doesn't exist"), 404"""
