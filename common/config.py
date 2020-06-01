from application import app

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///theaters.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# key for sessions
app.config['SECRET_KEY'] = b'\xc2\xa4YA\x1d\x0c\xb5?\xdf\x88\xa0\xe6\x7fA\xb4O'

# Basic Auth Settings
app.config['BASIC_AUTH_USERNAME'] = 'txstate'
app.config['BASIC_AUTH_PASSWORD'] = 'txstate'
app.config['BASIC_AUTH_FORCE'] = True  # makes the user/password site wide.

# Flask Admin settings
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

# Flask Security settings
app.config['SECURITY_URL_PREFIX'] = '/admin'
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = 'IIUHF0asdfkl98VHGlasdkl'
app.config['SECURITY_LOGIN_URL'] = '/login/'
app.config['SECURITY_LOGOUT_URL'] = '/logout/'
app.config['SECURITY_REGISTER_URL'] = '/register/'
app.config['SECURITY_POST_LOGIN_VIEW'] = '/admin/'
app.config['SECURITY_POST_LOGOUT_VIEW'] = '/admin/'
app.config['SECURITY_POST_REGISTER_VIEW'] = '/admin/'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

# JWT settings
app.config['JWT_SECRET_KEY'] = 'itHasToBeSECRETandDontTellAnyOne'
