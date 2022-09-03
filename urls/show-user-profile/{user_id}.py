
"""
here we take the "user_id" variable from the URL and use it to fetch the user from the database, if the "user_id" doesn't match any user, the it will returns "404 Not found" page
"""
@app.route('DefaultRoutePlaceHolder')
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(user_id)})
    if user:
        user['id']=str(user['_id'])
        del user['_id']
    else:
        return flask.abort(404)
    return flask.render_template('show-user-profile/{user_id}.html',user=user)
    
