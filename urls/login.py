
"""
in the login process , as always , we will check if the email and password hash matches any in the database. if it does, then a user session will start and the whole informations from the user fetched will be added to the seesion for easy loading for the infos instead of loading them from the database each time !
"""
@app.route('DefaultRoutePlaceHolder', methods=['GET', 'POST'])
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    if request.method=='POST':
        user=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email'),'password':PasswordsAPI.encrypt(request.form.get('password'))})
        if user:
            user['id']=str(user['_id'])
            del user['_id']
            SessionAPI.start_user_session(session,dict(user))
            return redirect('/')
        else:
            flask.flash(flask_admin.babel.gettext('incorrect email/password.'), 'error')
    return flask.render_template('login.html')
    
