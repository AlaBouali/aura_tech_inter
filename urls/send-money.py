
"""
first, we load all users and collect all their emails to pass them to the template where they will be useful for searching for the user to send money to (autosearch with js).
when the POST request is sent, wecheck if the amount of the money is in the correct range (0,current user's balance). then we get 2 variables for each user (sender/receiver) and update their balanes.

"""

@app.route('DefaultRoutePlaceHolder', methods=['GET', 'POST'])
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    users=MongoDbAPI.mongo_read_all('Users')
    emails=[]
    if users:
        for user in users:
            for x in user:
                if x=='email' and user[x]!=SessionAPI.get_user_variable(session,'email'):
                    emails.append(user[x])
    else:
        emails=[]
    if request.method=='POST':
        if int(request.form.get('amount',0)) in range(SessionAPI.get_user_variable(session,'balance')):
            old_recv=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
            old_send=MongoDbAPI.mongo_read_one('Users',{"email": SessionAPI.get_user_variable(session,'email')})
            new_recv=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
            new_send=MongoDbAPI.mongo_read_one('Users',{"email": SessionAPI.get_user_variable(session,'email')})
            new_recv['balance']=int(old_recv['balance'])+int(request.form.get('amount',0))
            new_send['balance']=int(old_send['balance'])-int(request.form.get('amount',0))
            MongoDbAPI.mongo_update_one('Users',old_send,new_send)
            MongoDbAPI.mongo_update_one('Users',old_recv,new_recv)
            SessionAPI.set_user_variables(session,{'balance':new_send['balance']})
        else:
            flask.flash(flask_admin.babel.gettext('No enough money.'), 'error')
    return flask.render_template('send-money.html',users=emails)
    
