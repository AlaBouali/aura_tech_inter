
"""
here we are going to:

1- fetch 2 variables for the same/current user
2- check if the "old_password" hash is the same as user's current password's hash
3- if they match , then we are going to create a new password hash and place it in one of the variables mentioned earlier (new_user) and finally update the user's records, else a flash message will display an error
"""
@app.route('DefaultRoutePlaceHolder', methods=['GET', 'POST'])
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    #print(session)
    if request.method=='POST':
        old_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        new_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        if PasswordsAPI.encrypt(request.form.get('old_password'))==old_user['password']:
            new_user['password']=PasswordsAPI.encrypt(request.form.get('new_password'))
            MongoDbAPI.mongo_update_one('Users',old_user,new_user)
            flask.flash(flask_admin.babel.gettext('password changed successfully.'), 'success')
        else:
            flask.flash(flask_admin.babel.gettext('incorrect old password.'), 'error')
    return flask.render_template('change_pwd.html')
    
