from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token,create_refresh_token, jwt_refresh_token_required,get_jwt_identity)
from application.accounts import User
from flask_security.utils import verify_password


class ApiLogin(Resource):
    # defining the request parser and the expected arguments in the request
    parser = reqparse.RequestParser()
    parser.add_argument('username',
                        type= str,
                        required=True,
                        help="This field cannot be blank")
    parser.add_argument('password',
                        type= str,
                        required= True,
                        help="This field cannot be blank")

    def post(self):
        data=self.parser.parse_args()
        # read from database to find the user and then check the password
        user = User.find_by_username(data['username'])
        if user and verify_password(data['password'], user.password):
            # when authenticate, return a fresh access token and a refresh the password
            access_token= create_access_token(identity=user.id, fresh=True)
            refresh_token  = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200
        return {"mensaje": "Invalid Credentials"}, 401


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        # retrieve the user's identity from the refresh token using a Flask JWT-Extended built-in method
        current_user = get_jwt_identity()
        # return a non-fresh token for the user
        new_token = create_access_token(identity=current_user,fresh=False)
        return {'access_token': new_token }, 200