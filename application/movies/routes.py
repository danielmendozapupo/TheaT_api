from . import movies_api
from .controllers import OneMovie, Movielist

movies_api.add_resource(OneMovie, '/movie_')
movies_api.add_resource(Movielist, '/movies_')
movies_api.add_resource(Movielist)
