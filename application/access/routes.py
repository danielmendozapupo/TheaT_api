from application.access import access_api
from .controllers import ApiLogin

access_api.add_resource(ApiLogin, '/access')