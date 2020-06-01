from functools import wraps

from flask import Flask, jsonify, request, flash, redirect, url_for, session, render_template, make_response, g
from flask_jwt_extended import get_current_user
from flask_login import login_user, current_user
from flask_security import logout_user
from sqlalchemy import update
from application import app, db
from application.forms import LoginForm, RegisterForm
from application.movies.models import Movies, movies_schema, movie_schema
from application.accounts.models import User, users_schema, user_schema
from application import loginMng
from flask_restful import Resource


@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template("index.html", index=True)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and user.get_password(password):
            #flash(f"{user.first_name}, you are successfully logged in!", "success")
            session['user_id'] = user.id
            session['username'] = user.first_name
            user.active = user.is_active
            session['active'] = user.active
            db.session.commit()
            return jsonify({'message': ' You successfully logged in! '})
            # return redirect(url_for('index'))
        else:
            flash("Sorry, something went wrong.", "danger")
            return redirect(url_for('login'))
    # return render_template("login.html", title="Login", login=True)
    return render_template("login.html", title="Login", form=form, login=True)


@app.route("/register", methods=['POST', 'GET'])
def register():
    if session.get('username'):
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        user = User(email=email, first_name=first_name, last_name=last_name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("You are successfully registered!", "success")
        return redirect(url_for('login'))
    return render_template("register.html", title="Register", form=form, register=True)


@app.route('/me', methods=['GET'])
#@login_required
@loginMng.user_loader
def load_user():
    if not session['user_id']:
        return jsonify("There is no active user at the moment")
    else:
        user = User.query.filter_by(id=session['user_id']).first()
        result = user_schema.dump(user)
        return jsonify(result)

#Check this later
@app.route('/users', methods=['GET'])
#@login_required
def get_users():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)


@app.route("/logout")

def logout():
    user = User.query.filter_by(id=session['user_id']).first()
    user.active = False
    session['user_id'] = False
    session['active'] = False
    session.pop('username', None)
    db.session.commit()
    return redirect(url_for('index'))


@app.route("/locations")
def locations():
    return render_template("locations.html", locations=True)


@app.route("/movies")
def movies():
    return render_template("movies.html", movies=True)


'''
@app.route('/movie_list')
def movie_list():
    return 0
'''


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", dashboard=True)


@app.route("/foodandDrinks")
def foodandDrinks():
    return render_template("foodandDrinks.html", foodandDrinks=True)


@app.route("/seats")
def seats():
    return render_template("seats.html", seats=True)


@app.route('/not_found')
def not_found():
    return jsonify(message='That resource was not found!'), 404


@app.route('/url_variables/<string:name>/<int:age>')
def url_variables(name: str, age: int):
    if age < 18:
        return jsonify(message='Sorry you are not all enough.'), 401
    else:
        return jsonify(message='Welcome ' + name + ', you are old enough!')


"""


@app.route('/not_found')
def not_found():
    return jsonify(message='That resource was not found!'), 404


@app.route('/parameters')
def parameters():
    name = request.args.get('name')
    age = request.args.get('age')
    if age < 18:
        return jsonify(message='Sorry you are not all enough.'), 401
    else:
        return jsonify(message='Welcome ' + name + ', you are old enough!')


@app.route('/url_variables/<string:name>/<int:age>')
def url_variables(name: str, age: int):
    if age < 18:
        return jsonify(message='Sorry you are not all enough.'), 401
    else:
        return jsonify(message='Welcome ' + name + ', you are old enough!')
        """

'''
@app.route('/movies', methods=['GET'])
def movies():
    movies_list = Movies.query.all()
    result = movies_schema.dump(movies_list)
    return jsonify(result)
'''

"""
@app.route('/register', methods=['POST'])
def register():
    if session.get('username'):
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        user = User(first_name=first_name, last_name=last_name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("You are successfully registered", "success")
        return redirect(url_for('index'))
        #return jsonify(message='User created successfully!'), 201
    else:
        flash("That email already exist!")
        return render_template("register.html", title="Register", form=form, register=True)
        #return jsonify(message='That email already exists.')



"""
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

'''
@app.route("/login", methods=['GET', 'POST'])
def login():
    if session.get('username'):
        return redirect(url_for('index'))

    form = LoginForm()
    #if request.method == 'POST':
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.objects(email=email).first()
        if user and user.get_password(password):
            flash("{user.first_name}, you are successfully logged in!", "success")
            session['user_id'] = user.user_id
            session['username'] = user.first_name
            return redirect(url_for('index'))
        else:
            flash("Sorry, something went wrong.", "danger")
            return render_template("login.html", title="Login", form=form, login=True)
        #return jsonify(message="Logged in successfully!")
        return render_template(url_for('index'))

    else:
        return render_template("login.html", title="Login", form=form, login=True)

@app.route("/logout")
def logout():
    session['user_id'] = False
    session.pop('username', None)
    return redirect(url_for('index'))

'''

"""
@app.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.get(
                User.email == form.email.data
            )
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You're now logged in!")
            else:
                flash("No user with that email/password combo")
        except NoResultFound:
            flash("No user with that email/password combo")
    return render_template('register.html', form=form)


@app.route('/secret')
@login_required
def secret():
    return "I should only be visible to logged-in accounts"


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/me')
def me_api():
    user = get_current_user()
    return jsonify(user)
    '''return {
        "user id": user.id,
        "User first name": user.first_name,
        "User last name": user.last_name,
        "user email":   user.email
    }'''


@app.route('/accounts', methods=['GET'])
def users():
    users_list = User.query.all()
    result = users_schema.dump(users_list)
    return jsonify(result)


@app.route('/retrieve_password/<string:email>', methods=['GET'])
def retrieve_password(email: str):
    user = User.query.filter_by(email=email).first()
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
    movie = Movies.query.filter_by(movie_id=movie_id).first()
    if movie:
        result = movie_schema.dump(movie)
        return jsonify(result)
    else:
        return jsonify(message="That movie doesn't exist"), 404


@app.route('/add_movie', methods=['POST'])
@jwt_required
def add_movie():
    movie_name = request.form['movie_name']
    test = Movies.query.filter_by(movie_name=movie_name).first()
    if test:
        return jsonify(message="There is already a movie by that name"), 409
    else:
        movie_name = request.form['movie name']
        movie_genre = request.form['movie_genre']
        movie_director = request.form['movie_director']
        movie_year = request.form['movie_year']

        new_movie = Movies(movie_name=movie_name,
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
    movie = Movies.query.filter_by(movie_id=movie_id).first()
    if movie:
        movie.movie_name = request.form['movie_name']
        movie.movie_genre = request.form['movie_genre']
        movie.movie_director = request.form['movie_director']
        movie.movie_year = request.form['movie_year']
        db.session.commit()
        return jsonify(message="You updated a movie!"), 202
    else:
        return jsonify(message="The movie doesn't exists!"), 404


@app.route('/remove_movie/<int:movie_id>', methods=['DELETE'])
@jwt_required
def remove_movie(movie_id: int):
    movie = Movies.query.filter_by(movie_id=movie_id).first()
    if movie:
        db.session.delete(movie)
        db.session.commit()
        return jsonify(message="Movie deleted!"), 202
    else:
        return jsonify(message="The movie doesn't exist"), 404

"""
