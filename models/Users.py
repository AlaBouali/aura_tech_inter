class UsersForm(SecureModelForm):
    firstname = WTFormsFields.StringField('firstname')
    lastname = WTFormsFields.StringField('lastname')
    email = WTFormsFields.StringField('email')
    telephone = WTFormsFields.StringField('telephone')
    balance = WTFormsFields.StringField('balance')


class UsersViewAdmin(AdminDashbordModelViewAdminMongodb):
    MODEL_NAME='Users'
    column_list = ('firstname', 'lastname', 'email', 'telephone', 'password','image','balance')
    column_sortable_list = ('firstname', 'lastname', 'email', 'telephone','password','image','balance')
    form = UsersForm

    def _list_thumbnail(view, context, model, name):
        if model.get('image',None)==None:
            return '/static/user_uploads/user_avatar.png'
        return jinja2.Markup('<img src="%s" width="64" height="64">' % (model['image']))

    column_formatters = {
        'image': _list_thumbnail
    }



class UsersViewEditor(AdminDashbordModelViewEditorMongodb):
    MODEL_NAME='Users'
    column_list = ('firstname', 'lastname', 'email', 'telephone', 'password','image','balance')
    column_sortable_list = ('firstname', 'lastname', 'telephone','email', 'password','image','balance')
    form = UsersForm

    def _list_thumbnail(view, context, model, name):
        if model.get('image',None)==None:
            return '/static/user_uploads/user_avatar.png'
        return jinja2.Markup('<img src="%s" width="64" height="64">' % (model['image']))

    column_formatters = {
    'image': _list_thumbnail
    }





if AdminDashboardSettings.ADMIN_PANEL_ENABLED==True:
    AdminDashboardApp.add_view(UsersViewAdmin(db_mongo['Users'], 'Users',endpoint='Users_Admin'))
    AdminDashboardApp.add_view(UsersViewEditor(db_mongo['Users'], 'Users',endpoint='Users_Editor'))

