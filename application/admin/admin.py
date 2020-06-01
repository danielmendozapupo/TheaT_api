from application import app, db
from flask import url_for, redirect, request, abort
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_security import current_user
from application.movies import Movies, Genre
from application.accounts import User, Role
from flask_bootstrap import Bootstrap
from flask_security import Security, SQLAlchemyUserDatastore
from flask_admin import helpers as admin_helpers

# Flask Admin
admin = Admin(app, name='Admin', base_template='my_master.html', template_mode='bootstrap3')

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Define a context processor for merging flask-admin template content into the
# flask-security views
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )


# Custom modelview for Flask-Security
class AppModelView(ModelView):
    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('superuser')
                )

    def _handle_view(self, name, **kwargs):
        """
        override built-in _handle_view in order to redirect user when a view is not accessible
        :param name:
        :param kwargs:
        :return:
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('login', next=request.url))


# admin views
secure = True
if secure:
    admin.add_view(AppModelView(Movies, db.session))
    admin.add_view(AppModelView(Genre, db.session))
    admin.add_view(AppModelView(User, db.session))
    admin.add_view(AppModelView(Role, db.session))
else:
    User.add_view(AppModelView(Movies, db.session))
    User.add_view(AppModelView(Genre, db.session))
    User.add_view(AppModelView(User, db.session))
    User.add_view(AppModelView(Role, db.session))
