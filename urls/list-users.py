
"""
This page will load all the users in the database and pass them as a list to the template "list-users.html" where their full names are hyper links with this format: /show-user-profile/<user_id>
"""
@app.route('DefaultRoutePlaceHolder')
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    users=MongoDbAPI().mongo_read_all('Users')
    if users:
        for user in users:
            user['id']=str(user['_id'])
            del user['_id']
    else:
        users={}
    return flask.render_template('list-users.html',users=users)
    
