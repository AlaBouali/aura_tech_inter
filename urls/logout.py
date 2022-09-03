

@app.route('DefaultRoutePlaceHolder', methods=['GET', 'POST'])
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    SessionAPI.end_user_session(session)
    return redirect('/')