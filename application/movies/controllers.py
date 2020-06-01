from flask_restful import Resource, reqparse
from .models import Movies, movie_schema, movies_schema, Genre
from flask import abort, jsonify
from application import db, api
from flask_jwt_extended import jwt_required, jwt_refresh_token_required, get_jwt_identity, create_access_token


class OneMovie(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('movie_id', type=int, required=True)
        self.args = parser.parse_args()

        movie = Movies.query.filter_by(Movies.id == self.args['movie_id']).first()
        if not movie:
            return abort(404, 'Movie with id: {} does not exist in the database'.format(self.args['movie_id']))
        return jsonify(movies=movie_schema.dump(movie))

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('movie_title', type=str, required=True)
        parser.add_argument('genre_id', type=int, required=True)
        parser.add_argument('movie_director', type=int, required=True)
        parser.add_argument('movie_year', type=str, required=True)
        parser.add_argument('movie_age', type=int, required=True)
        self.args = parser.parse_args()

        movie_title = self.args['movie_title']
        genre_id = self.args['genre_id']

        existing_movie = Movies.query.filter_by(Movies.movie_title == movie_title).first()
        if existing_movie:
            return abort(404, 'Movie with title: {} already exists in the database.'.format(self.args['movie_title']))

        movie = Movies(movie_title=movie_title,
                       genre_id=genre_id)
        try:
            db.session.add(movie)
            db.session.commit()
        except:
            return abort(500, 'An error occurred while trying to add new movie to database.')
        return jsonify(message="New movie has been added to the database.")


class Movielist(Resource):
    #@jwt_required
    def get(self):
        movies = Movies.query.all()
        return jsonify(movies=movies_schema.dump(movies))


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        # retrieve the user's identity from the refresh token using a Flash JWT-Extended built-in method
        current_user = get_jwt_identity()
        # return a non fresh token for the user
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200



    """
    @app.route('/movies', methods=['GET'])
    def movies():
        movies_list = movies.Movies.query.all()
        result = movies_schema.dump(movies_list)
        return jsonify(result)
    """
