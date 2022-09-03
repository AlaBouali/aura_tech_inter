import os,pathlib,random,re


def load_file(f):
    with open(f,'r') as fi:
        d=fi.read()
        fi.close()
    return d

def add_script(s):
    return s+'\n\n\n'


def exec_app(script,globals_):
    exec(script, globals_)




def get_all_python_files(path):
    l=[]
    for path, subdirs, files in os.walk(path):
        for name in files:
            file='/'.join(pathlib.Path(os.path.join(path, name)).parts)
            if file.endswith('.py') and file!='urls/index.py':
                l.append(file)
    return l


"""
(this is inspired from NextJS)
for each route file, we will give it: function name and a path depending on its location:

urls/login.py ==> /login && /login/

urls/register.py ==> /register && /register/

while keeping the same function body for both paths !

even the dynamic routes are possible:

urls/show-user-profile/{user_id} ==> /show-user-profile/<user_id> && /show-user-profile/<user_id>/

this will make adding / editing / fixing / deleting each site functionality so easy !
"""
def load_route(path,script_location,second=False):
    script=open(script_location).read()
    url_vars=[]
    pattern = re.compile(r"{(.*)}")
    url_vars+=list(pattern.findall(path))
    vars_str=''
    vars_str=','.join(url_vars)
    script=script.replace('DefaultRoutePlaceHolder',path.replace('{','<').replace('}','>'))
    script=script.replace('DefaultVarsPlaceHolder',vars_str)
    route_functionpath=script_location.replace('.','_').replace('-','_').replace('{','_').replace('}','_')
    if second==True:
        route_functionpath+='_'
    script=script.replace('DefaultRouteFunctionPlaceHolder',str('_'.join(route_functionpath.lower().split('/'))+'_').lower())
    return add_script(script)


def load_all_routes():
    s=''
    try:
        s+=load_route('/','urls/index.py')
    except Exception as e:
        pass
    URL_FILES=get_all_python_files('urls')
    for x in URL_FILES:
        a,b=os.path.split(x.split('.py')[0])
        if len(b.split('.'))<2:
            s+=load_route(x.split('urls')[1].split('.py')[0],x)
            s+=load_route(x.split('urls')[1].split('.py')[0]+'/',x,second=True)
        else:
            s+=load_route(x.split('urls')[1].split('.py')[0],x)
    f = open("routes.py", "w")
    f.write(s)
    f.close()
    return s



def build_app():
    #first we fech all code base from 'src/base.py' file to use all its classes, static variables and static functions in the next files
    s=load_file('src/base.py')
    #if there is any files to include after the code base is loaded then they go here
    INCLUDED_FILES=get_all_python_files('includes')
    #load all models from models folder to the main script
    for x in INCLUDED_FILES:
        s+=load_file(x)
    INCLUDED_FILES=get_all_python_files('models')
    for x in INCLUDED_FILES:
        s+=load_file(x)
    #load all the routes after doing the ncessary changes
    s+=load_all_routes()
    #now we add last touches to the code
    s+="""
# now we will run the application

if AdminDashboardSettings.ADMIN_PANEL_ENABLED==True:
    for x in ServerSettings["ADMIN_PANEL_CATEGORIES"]:
        AdminDashboardApp.add_category(**x)

    for x in ServerSettings["ADMIN_PANEL_SUBCATEGORIES"]:
        AdminDashboardApp.add_category(**x)

    for x in ServerSettings['ADMIN_PANEL_LANGUAGE_OPTIONS']:
        AdminDashboardApp.add_link(NormalMenuLink(url=AdminDashboardSettings.ADMIN_PANEL_SET_LANGUAGE_URL+'/'+x,**ServerSettings['ADMIN_PANEL_LANGUAGE_OPTIONS'][x]))

    for x in ServerSettings["ADMIN_PANEL_LINKS_ORDER"]:
        for i in ServerSettings[x]:
            if x=="ADMIN_PANEL_AUTHENTICATED_LINKS":
                AdminDashboardApp.add_link(AuthenticatedMenuLink(**i))
            if x=="ADMIN_PANEL_UNAUTHENTICATED_LINKS":
                AdminDashboardApp.add_link(UnauthenticatedMenuLink(**i))
            if x=="ADMIN_PANEL_NORMAL_LINKS":
                AdminDashboardApp.add_link(NormalMenuLink(**i))
            if x=="ADMIN_PANEL_SUPER_ADMIN_LINKS":
                AdminDashboardApp.add_link(SuperAdminMenuLink(**i))
            if x=="ADMIN_PANEL_EDITOR_ADMIN_LINKS":
                AdminDashboardApp.add_link(EditorAdminMenuLink(**i))




try:
    db.create_all()
except:
    pass




# if the Admins' table is empty when starting the app then a default account is created and creating the roles also
try:
        if len(db.session.query(Admins).all())==0:
            db.session.add(Admins(**AdminDashboardSettings.DEFAULT_ADMIN_LOGIN_CREDENTIALS))
            db.session.commit()
except:
        pass



if __name__ == '__main__':
    app.run(**AppRunSettings)"""
    f = open("full_source_code.py", "w")
    f.write(s)
    f.close()
    return s

#we run the whole code as a single script in the RAM after loading all necessary components
exec_app(build_app(),globals())
