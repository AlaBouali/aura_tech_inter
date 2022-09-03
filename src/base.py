import flask,flask_admin,flask_sqlalchemy,sqlalchemy,json,sys,random,os,flask_recaptcha,werkzeug,pymongo,jinja2,hashlib

from wtforms import fields as WTFormsFields

from flask import flash
from bson import ObjectId
from bson.errors import InvalidId


import boto3, botocore

from flask_admin.contrib.sqla import ModelView as FlaskAdminModelView

from flask_admin.contrib.pymongo.filters import BasePyMongoFilter
from flask_admin.contrib.pymongo.tools import parse_like_term

from flask_admin.helpers import (get_form_data, validate_form_on_submit,
                                 get_redirect_target, flash_errors)

from flask_admin.model.helpers import prettify_name, get_mdict_item_or_list

from flask_admin.form import FormOpts


from flask_wtf.file import FileField

from flask import Flask,session,request,redirect,render_template

import requests
import flask_recaptcha ,sqlalchemy

import flask_limiter
from flask_limiter.util import get_remote_address



from flask_admin._compat import string_types
from flask_admin.babel import gettext, ngettext, lazy_gettext
from flask_admin.actions import action
from flask_admin.helpers import get_form_data




def werkzeug_wrappers_request_Request_close(*args,**kwargs):
    files = args[0].__dict__.get("files")
    for _key, value in werkzeug.datastructures.iter_multi_items(files or ()):
        print(type(value))
        if type(value)!=str:
            value.close()


werkzeug.wrappers.request.Request.close=werkzeug_wrappers_request_Request_close




import flask_mail

import json,os,random,sys,datetime,ssl,mimetypes,time,logging

import sqlalchemy_utils 


from logging.handlers import RotatingFileHandler


from firebase_admin import auth as FirebaseAuthAPI


import firebase_admin

import sanitizy


import hashlib,functools

from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer,SecureCookieSessionInterface



from google.cloud import storage as GoogleCloudStorage


def ReadAppConfigs():
    f = open('config.json', encoding="utf8")
    d = json.load(f)
    f.close()
    return d



app = Flask(__name__)

AppConfigs=ReadAppConfigs()




AppRunSettings=AppConfigs['app']


ServerSettings=AppConfigs['server']


if ServerSettings['RECAPTCHA_SECRET_KEY']!=None:
    ServerSettings.update({'RECAPTCHA_ENABLED': True})
else:
    ServerSettings.update({'RECAPTCHA_ENABLED': False})

app.config.update(**ServerSettings)



EndpointsRateLimit=flask_limiter.Limiter(app, key_func=get_remote_address, default_limits=[])



db=flask_sqlalchemy.SQLAlchemy(app)

db_mongo=None

if ServerSettings['MONGODB_URI'] and ServerSettings['MONGODB_URI'].strip()!='':
    db_mongo = pymongo.MongoClient(ServerSettings['MONGODB_URI'])[ServerSettings['MONGODB_URI'].split('://')[1].split('/')[1].split('?')[0]]
    

# the following lines check if our database exists on the SQL server, if it does not then it creates it

if not sqlalchemy_utils.database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
 sqlalchemy_utils.create_database(app.config['SQLALCHEMY_DATABASE_URI'])



#this class is responsible for translating any predefined words/sentences in the dictionairy in the "config.json" file to the corresponding language for both: user / admin

class TranslateInTemplate:

    TranslateDict=ServerSettings['TRANSLATEDICT']
    DEFAULT_ADMIN_PANEL_LANGUAGE=ServerSettings['DEFAULT_ADMIN_PANEL_LANGUAGE']
    ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER=ServerSettings['ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER']

    @staticmethod
    def TranslateWord_Admin(s,word):
        try:
            return TranslateInTemplate.TranslateDict[word][s.get('admin_session',{}).get(TranslateInTemplate.ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER,TranslateInTemplate.DEFAULT_ADMIN_PANEL_LANGUAGE)]
        except:
            return word

    def TranslateWord_User(s,word):
        try:
            return TranslateInTemplate.TranslateDict[word][s.get('user_session',{}).get(TranslateInTemplate.ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER,TranslateInTemplate.DEFAULT_ADMIN_PANEL_LANGUAGE)]
        except:
            return word



app.jinja_env.globals.update(TranslateWord=TranslateInTemplate.TranslateWord_Admin)


app.jinja_env.globals.update(TranslateWordUser=TranslateInTemplate.TranslateWord_User)



def get_real_url_path(path):
    return  '/'+'/'.join([ x for x in str(path).split('?')[0].split('/') if x.strip()!=''])+'/'


#function to generate random string



def random_string(s):
    return ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') for x in range(s)])



def list_contains(l,s):
    return any(x.startswith(s) for x in l)



class SecureModelForm(flask_admin.form.SecureForm):
    pass


#this class is used to create passwords hashes before storing them in the database, or to compare between the stored hash and the produced one from user input

class PasswordsAPI:

    PASSWORD_HASH_SALT=ServerSettings['PASSWORD_HASH_SALT']

    @staticmethod
    def encrypt(password):
        return hashlib.sha256('{}{}{}'.format(PasswordsAPI.PASSWORD_HASH_SALT,password,PasswordsAPI.PASSWORD_HASH_SALT).encode()).hexdigest()

    @staticmethod
    def compare(user_input,password_hash):
        return PasswordsAPI.encrypt(user_input)==password_hash



#defining the admin panel's base url , ex: /admin  ,  /admin_login  ,  /admin_panel  ....

class AdminDashboardSettingsBaseURL:

    ADMIN_PANEL_BASE_URL=get_real_url_path('/'+'/'.join([ x for x in [ x for x in ServerSettings["ADMIN_PANEL_UNAUTHENTICATED_LINKS"] if x['name']==ServerSettings['ADMIN_PANEL_LOGIN_LINK_NAME']][0]['url'].split('/')[:-1] if x.strip()!='']))



app.jinja_env.globals['ADMIN_PANEL_BASE_URL']=AdminDashboardSettingsBaseURL.ADMIN_PANEL_BASE_URL


app.jinja_env.globals['CSRF_TOKEN_NAME']=ServerSettings['CSRF_TOKEN_NAME']



#this class is used to upload files to an amazon S3 bucket

class Amazon_S3_API:
    aws_access_key_id=ServerSettings['S3_KEY']
    aws_secret_access_key=ServerSettings['S3_SECRET']
    S3_BUCKET=ServerSettings['S3_BUCKET']
    S3_LOCATION=ServerSettings['S3_LOCATION']
    s3=None
    if aws_access_key_id.strip()!='' and aws_secret_access_key.strip()!='':
        s3 = boto3.client(
            "s3",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    @staticmethod
    def upload_file_to_s3(file, bucket_name, acl="public-read"):
        """
        Docs: http://boto3.readthedocs.io/en/latest/guide/s3.html
        """
        try:
            Amazon_S3_API.s3.upload_fileobj(
                file,
                bucket_name,
                file.filename,
                ExtraArgs={
                    "ACL": acl,
                    "ContentType": file.content_type    #Set appropriate content type as per the file
                }
            )
        except Exception as e:
            print("Something Happened: ", e)
            return e
        return "{}{}".format(Amazon_S3_API.S3_LOCATION, file.filename)

    @staticmethod
    def save_file(file):
        file.filename = FileManagerAPI.secure_filename(file.filename)
        output = Amazon_S3_API.upload_file_to_s3(file, app.config["S3_BUCKET"])
        return str(output)


#in this class we store most of the admin panel's configs in static variables to protect them when working with such large projects

class AdminDashboardSettings:

    ADMIN_AVATAR_HEIGHT=ServerSettings['ADMIN_AVATAR_HEIGHT']
    ADMIN_AVATAR_WIDTH=ServerSettings['ADMIN_AVATAR_HEIGHT']
    ADMIN_APP_TEMPLATES_FOLDER=ServerSettings['ADMIN_APP_TEMPLATES_FOLDER']
    ADMINDASHBOARDVIEW_SETTINGS=ServerSettings['ADMINDASHBOARDVIEW_SETTINGS']
    ADMIN_APP_SETTINGS=ServerSettings['ADMIN_APP_SETTINGS']
    READ_ONLY_MODE=ServerSettings['ADMIN_PANEL_EDIT_DISABLED']
    ADMIN_PANEL_ENABLED=ServerSettings['ADMIN_PANEL_ENABLED']
    ADMIN_PANEL_RECAPTCHA_ENABLED=ServerSettings['ADMIN_PANEL_RECAPTCHA_ENABLED']
    ADMIN_PANEL_SUPER_ADMIN_LINKS=[ get_real_url_path(x['url'].split('{')[0]) for x in ServerSettings["ADMIN_PANEL_SUPER_ADMIN_LINKS"]]
    ADMIN_PANEL_EDITOR_ADMIN_LINKS=[ get_real_url_path(x['url'].split('{')[0]) for x in ServerSettings["ADMIN_PANEL_EDITOR_ADMIN_LINKS"]]
    ADMIN_PANEL_AUTHENTICATED_LINKS=[ get_real_url_path(x['url'].split('{')[0]) for x in ServerSettings["ADMIN_PANEL_AUTHENTICATED_LINKS"]]
    ADMIN_PANEL_UNAUTHENTICATED_LINKS=[ get_real_url_path(x['url'].split('{')[0]) for x in ServerSettings["ADMIN_PANEL_UNAUTHENTICATED_LINKS"]]
    ADMIN_PANEL_NORMAL_LINKS=[ get_real_url_path(x['url'].split('{')[0]) for x in ServerSettings["ADMIN_PANEL_NORMAL_LINKS"]]
    ADMIN_PANEL_BASE_URL=AdminDashboardSettingsBaseURL.ADMIN_PANEL_BASE_URL
    ADMIN_PANEL_LOGIN_FULL_PATH=[ x for x in ServerSettings["ADMIN_PANEL_UNAUTHENTICATED_LINKS"] if x['name']==ServerSettings['ADMIN_PANEL_LOGIN_LINK_NAME']][0]['url']
    ADMIN_PANEL_LOGOUT_FULL_PATH=[ x for x in ServerSettings["ADMIN_PANEL_AUTHENTICATED_LINKS"] if x['name']==ServerSettings['ADMIN_PANEL_LOGOUT_LINK_NAME']][0]['url']
    ADMIN_PANEL_CHANGE_PASSWORD_FULL_PATH=[ x for x in ServerSettings["ADMIN_PANEL_AUTHENTICATED_LINKS"] if x['name']==ServerSettings['ADMIN_PANEL_CHANGE_PASSWORD_LINK_NAME']][0]['url']
    ADMIN_PANEL_PROFILE_FULL_PATH=[ x for x in ServerSettings["ADMIN_PANEL_AUTHENTICATED_LINKS"] if x['name']==ServerSettings['ADMIN_PANEL_PROFILE_LINK_NAME']][0]['url']
    ADMIN_PANEL_LOGIN_TEMPLATE=ServerSettings["ADMIN_PANEL_LOGIN_TEMPLATE"]
    ADMIN_PANEL_INDEX_TEMPLATE=ServerSettings["ADMIN_PANEL_INDEX_TEMPLATE"]
    ADMIN_PANEL_PROFILE_TEMPLATE=ServerSettings["ADMIN_PANEL_PROFILE_TEMPLATE"]
    ADMIN_PANEL_CHANGE_PASSWORD_TEMPLATE=ServerSettings["ADMIN_PANEL_CHANGE_PASSWORD_TEMPLATE"]
    ADMIN_RETURN_HOME_LINK_NAME=ServerSettings['ADMIN_RETURN_HOME_LINK_NAME']
    DEFAULT_ADMIN_LOGIN_CREDENTIALS=ServerSettings['DEFAULT_ADMIN_LOGIN_CREDENTIALS']
    ADMIN_PANEL_SET_LANGUAGE_URL='/'+'/'.join([ x for x in str(AdminDashboardSettingsBaseURL.ADMIN_PANEL_BASE_URL+'/'+ServerSettings['ADMIN_PANEL_SET_LANGUAGE_URI']).split('/') if x.strip()!=''])
    ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER=ServerSettings['ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER']




class GoogleReCaptchaAPI:

    recaptcha_app =flask_recaptcha.ReCaptcha(app)
    recaptcha_app.init_app(app)
    invalid_recaptcha_response=ServerSettings['INVALID_RECAPTCHA_RESPONSE']
    invalid_recaptcha_response_api=ServerSettings['INVALID_RECAPTCHA_RESPONSE_API']
    invalid_recaptcha_code=ServerSettings['INVALID_CHECK_STATUS_CODE']

    @staticmethod
    def remove_recaptcha_response(obj):
        d={}
        for x in obj.form:
            if x!='g-recaptcha-response':
                d.update({x:obj.form[x]})
        obj.form=werkzeug.datastructures.ImmutableMultiDict(d)
        d={}
        for x in obj.args:
            if x!='g-recaptcha-response':
                d.update({x:obj.args[x]})
        obj.args=werkzeug.datastructures.ImmutableMultiDict(d)
        for x in obj.files:
            if x!='g-recaptcha-response':
                d.update({x:obj.files[x]})
        obj.files=werkzeug.datastructures.ImmutableMultiDict(d)

    @staticmethod
    def valid_recaptcha(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if GoogleReCaptchaAPI.recaptcha_app.verify():
                GoogleReCaptchaAPI.remove_recaptcha_response(request)
                return f(*args, **kwargs)
            else:
                GoogleReCaptchaAPI.remove_recaptcha_response(request)
                return GoogleReCaptchaAPI.invalid_recaptcha_response,GoogleReCaptchaAPI.invalid_recaptcha_code
        return validate

    def valid_recaptcha_api(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if GoogleReCaptchaAPI.recaptcha_app.verify():
                GoogleReCaptchaAPI.remove_recaptcha_response(request)
                return f(*args, **kwargs)
            else:
                GoogleReCaptchaAPI.remove_recaptcha_response(request)
                return GoogleReCaptchaAPI.invalid_recaptcha_response_api,GoogleReCaptchaAPI.invalid_recaptcha_code
        return validate

# for recaptcha's HTML code : https://developers.google.com/recaptcha/docs/display

# https://www.google.com/recaptcha/

# <script src="https://www.google.com/recaptcha/api.js" async defer></script>




class FileManagerAPI:

    allowed_extensions=ServerSettings['ALLOWED_EXTENSIONS']
    allowed_mimetypes=ServerSettings['ALLOWED_MIMETYPES']
    default_user_upload_folder=ServerSettings['DEFAULT_USER_UPLOAD_FOLDER']

    @staticmethod
    def secure_filename(f):
        return sanitizy.FILE_UPLOAD.secure_filename(f)

    @staticmethod
    def file_exists(path):
        return os.path.exists(path)

    @staticmethod
    def create_dir_file(path,exist_ok=True):
        if not os.path.exists(path):
            os.makedirs(path)

    @staticmethod
    def delete_file(w):
        if os.path.exists(w):
            os.remove(w)

    @staticmethod
    def create_file(w):
        direc,file=os.path.split(w)
        try:
            FileManagerAPI.create_dir_file(direc, exist_ok=True)
        except:
            pass
        with open(w ,"a+") as f:
            pass
        f.close()
        
    @staticmethod
    def read_file(fl):
        with open(fl,'rb') as f:
            content = f.read()
            f.close()
        return content
        
    @staticmethod
    def valid_uploaded_file(f):
        return sanitizy.FILE_UPLOAD.check_file(f,allowed_extensions=FileManagerAPI.allowed_extensions,allowed_mimetypes=FileManagerAPI.allowed_mimetypes)

    @staticmethod
    def bind_path(*args):
        seperate='\\\\' if (sys.platform.lower() == "win32") or( sys.platform.lower() == "win64") else '/'
        return seperate.join(args)

    @staticmethod
    def save_file(f,path=None,args=None):
        if path==None or len(path.strip())==0:
            path=FileManagerAPI.default_user_upload_folder
        if args:
            if type(args)==str and len(args.strip())>0:
                path+='/'+args
            else:
                for x in args:
                    path+='/'+x
        FileManagerAPI.create_dir_file(path, exist_ok=True)
        return sanitizy.FILE_UPLOAD.save_file(f,path=path)

    @staticmethod
    def save_all_files(fs,path=None,args=None):
        return [ FileManagerAPI.save_file(x,path=path,args=args) for x in fs ]

    @staticmethod
    def download_file(path,root_dir='uploads',as_attachment=True):
        file=sanitizy.PATH_TRAVERSAL.safe_file(path,files_location=root_dir,logs=False,working_directory=None)
        if file!=None:
            return send_file(path, as_attachment=as_attachment)
        return None







class SessionAPI:

    permanent_session=ServerSettings['PERMANENT_SESSION']
    csrf_token_name=ServerSettings['CSRF_TOKEN_NAME']
    jwt_session_variable_name=ServerSettings['JWT_SESSION_VARIABLE_NAME']

    @staticmethod
    def set_cookie(res,key,value,attributes):
        res.set_cookie(key, value , **attributes)

    @staticmethod
    def dump_jwt_data_into_session(s,d):
        s[SessionAPI.jwt_session_variable_name]=data
        s.modified = True
        s.permanent = SessionAPI.permanent_session

    @staticmethod
    def load_jwt_data_from_session(s):
        return s.get(SessionAPI.jwt_session_variable_name,{})

    @staticmethod
    def set_session_variables(s,d):
        for x in d:
            s[x] = d[x]
        s.modified = True
        s.permanent = SessionAPI.permanent_session

    @staticmethod
    def reset_session(s):
        s.clear()
        s.modified = True
        s.permanent = SessionAPI.permanent_session

    @staticmethod
    def start_admin_session(s,variables={}):
        csrf=random_string(64)
        if s.get('admin_session',{})=={}:
            s['admin_session']={}
        s['admin_session'][SessionAPI.csrf_token_name]=csrf
        s['admin_session']['admin_logged_in_at']=time.time()
        s['admin_session'].update(variables)
        s.modified = True
        s.permanent = SessionAPI.permanent_session

    @staticmethod
    def end_admin_session(s):
        if s.get('admin_session',{})!={}:
            s['admin_session']['admin_logged_in_at']=0
            s.modified = True
            s.permanent = SessionAPI.permanent_session

    @staticmethod
    def start_user_session(s,variables={}):
        csrf=random_string(64)
        if s.get('user_session',{})=={}:
            s['user_session']={}
        s['user_session'][SessionAPI.csrf_token_name]=csrf
        s['user_session']['user_logged_in_at']=time.time()
        s['user_session'].update(variables)
        s.modified = True
        s.permanent = SessionAPI.permanent_session

    @staticmethod
    def end_user_session(s):
        if s.get('user_session',{})!={}:
            s['user_session']['user_logged_in_at']=0
            s.modified = True
            s.permanent = SessionAPI.permanent_session

    @staticmethod
    def get_user_variable(session,variable):
        return session.get('user_session',{}).get(variable,None)

    @staticmethod
    def get_user_variables(session,*args):
        d={}
        for x in session.get(SessionAPI.jwt_session_variable_name,{}):
            if x in args:
                d.update({x:s.get('user_session',{}).get(variable,None)})
        return d

    @staticmethod
    def get_admin_variable(s,variable):
        return s.get('admin_session',{}).get(variable,None)

    @staticmethod
    def get_admin_variables(s,*args):
        d={}
        for x in s:
            if x in args:
                d.update({x:s.get('admin_session',{}).get(variable,None)})
        return d

    @staticmethod
    def set_user_variables(s,variable):
        if s.get('user_session',{})=={}:
            s['user_session']={}
        s['user_session'].update(variable)
        s.modified = True
        s.permanent = SessionAPI.permanent_session

    @staticmethod
    def set_admin_variables(s,variable):
        if s.get('admin_session',{})=={}:
            s['admin_session']={}
        s['admin_session'].update(variable)
        s.modified = True
        s.permanent = SessionAPI.permanent_session


app.jinja_env.globals.update(get_admin_session_variable=SessionAPI.get_admin_variable)

app.jinja_env.globals.update(get_user_session_variable=SessionAPI.get_user_variable)




class JWTAuthenticationAPI:

    from jose import jwt
    algorithm=ServerSettings['JWT_ALGORITHM']
    secret_key=ServerSettings['JWT_SECRET_KEY']
    jwt_token_lifetime=ServerSettings['JWT_TOKEN_LIFETIME']
    jwt_session_variable_name=SessionAPI.jwt_session_variable_name

    @staticmethod
    def encode_data(data):
        data.update({'jwt_token_created_at':time.time()})
        return JWTAuthenticationAPI.jwt.encode(data,JWTAuthenticationAPI.secret_key,algorithm=JWTAuthenticationAPI.algorithm)

    @staticmethod
    def decode_token(token):
        return JWTAuthenticationAPI.jwt.decode(token,JWTAuthenticationAPI.secret_key,algorithms=[JWTAuthenticationAPI.algorithm])

    @staticmethod
    def get_variable(data,variable):
        return data.get(variable,None)

    @staticmethod
    def get_variables(data,*args):
        d={}
        for x in data:
            if x in args:
                d.update({x:data.get(x,None)})
        return d

    @staticmethod
    def get_variable_from_session(s,variable):
        if s.get(JWTAuthenticationAPI.jwt_session_variable_name,None)!=None:
            return s[JWTAuthenticationAPI.jwt_session_variable_name].get(variable,None)

    @staticmethod
    def get_variables_from_session(s,**args):
        d={}
        if s.get(JWTAuthenticationAPI.jwt_session_variable_name,None)!=None:
            for x in s[JWTAuthenticationAPI.jwt_session_variable_name]:
                if x in args:
                    d.update({x:data.get(x,None)})
        return d



#https://gist.github.com/babldev/502364a3f7c9bafaa6db




class FlaskSessionAPI:

    @staticmethod
    def decode_flask_token(cookie_str):
        serializer = TaggedJSONSerializer()
        signer_kwargs = {
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1
        }
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], serializer=serializer, signer_kwargs=signer_kwargs)
        return s.loads(cookie_str)

    @staticmethod
    def generate_flask_token(cookie,app=app):
        return SecureCookieSessionInterface().get_signing_serializer(app).dumps(dict(cookie))

# https://stackoverflow.com/questions/42283778/generating-signed-session-cookie-value-used-in-flask






class HeadersAPI:

    authorization_header=ServerSettings['AUTHORIZATION_HEADER']
    CORS_OPTIONS_HEADERS=ServerSettings['CORS_OPTIONS_HEADERS']
    CORS_HEADERS=ServerSettings['CORS_HEADERS']
    additional_headers=ServerSettings['ADDITIONAL_HEADERS']
    unwanted_headers=ServerSettings['UNWANTED_HEADERS']

    @staticmethod
    def set_headers(h,d):
        for x in d:
            h[x] = d[x]

    @staticmethod
    def unset_headers(h,d):
        for x in d:
            h[x]=''








class ValidatorsAPI:

    STORAGE_TYPE=ServerSettings['STORAGE_TYPE']
    USER_AUTHENTICATED_ENDPOINTS=[ get_real_url_path(x.split('{')[0]) for x in ServerSettings["USER_AUTHENTICATED_ENDPOINTS"]]
    USER_UNAUTHENTICATED_ENDPOINTS=[ get_real_url_path(x.split('{')[0]) for x in ServerSettings["USER_UNAUTHENTICATED_ENDPOINTS"]]
    RECAPTCHA_ENDPOINTS=[ get_real_url_path(x.split('{')[0]) for x in ServerSettings["RECAPTCHA_ENDPOINTS"]]
    AUTO_SAVE_FILES_ENDPOINTS=[ get_real_url_path(x.split('{')[0]) for x in ServerSettings["AUTO_SAVE_FILES_ENDPOINTS"]]
    CSRF_PROTECTED_USER_ENDPOINTS=[ get_real_url_path(x.split('{')[0]) for x in ServerSettings["CSRF_PROTECTED_USER_ENDPOINTS"]]
    user_session_lifetime=ServerSettings['USER_SESSION_LIFETIME']
    admin_session_lifetime=ServerSettings['ADMIN_SESSION_LIFETIME']
    csrf_token_name=ServerSettings['CSRF_TOKEN_NAME']
    unauthenticated_user_redirect=ServerSettings.get('UNAUTHENTICATED_USER_REDIRECT','/')
    authenticated_user_redirect=ServerSettings.get('AUTHENTICATED_USER_REDIRECT','/')
    unauthenticated_admin_redirect=AdminDashboardSettingsBaseURL.ADMIN_PANEL_BASE_URL if (ServerSettings['UNAUTHENTICATED_ADMIN_REDIRECT']==None or ServerSettings['UNAUTHENTICATED_ADMIN_REDIRECT'].strip()=='') else '/'+'/'.join([ x for x in ServerSettings['UNAUTHENTICATED_ADMIN_REDIRECT'].split('/') if x.strip()!=''])
    authenticated_admin_redirect=AdminDashboardSettingsBaseURL.ADMIN_PANEL_BASE_URL if (ServerSettings['AUTHENTICATED_ADMIN_REDIRECT']==None or ServerSettings['AUTHENTICATED_ADMIN_REDIRECT'].strip()=='') else '/'+'/'.join([ x for x in ServerSettings['AUTHENTICATED_ADMIN_REDIRECT'].split('/') if x.strip()!=''])
    accepted_referer_domains=ServerSettings['ACCEPTED_REFERER_DOMAINS']
    accepted_origin_domains=ServerSettings['ACCEPTED_ORIGIN_DOMAINS']
    allowed_extensions=FileManagerAPI.allowed_extensions
    allowed_mimetypes=FileManagerAPI.allowed_mimetypes
    jwt_token_lifetime=JWTAuthenticationAPI.jwt_token_lifetime
    invalid_check_code=ServerSettings['INVALID_CHECK_STATUS_CODE']
    invalid_session_response=ServerSettings['INVALID_SESSION_RESPONSE']
    invalid_session_response=ServerSettings['INVALID_SESSION_RESPONSE_API']
    invalid_flask_session_response=ServerSettings['INVALID_FLASK_SESSION_RESPONSE']
    invalid_flask_session_response_api=ServerSettings['INVALID_FLASK_SESSION_RESPONSE_API']
    invalid_referer_response=ServerSettings['INVALID_REFERER_RESPONSE']
    invalid_referer_response_api=ServerSettings['INVALID_REFERER_RESPONSE_API']
    invalid_origin_response=ServerSettings['INVALID_ORIGIN_RESPONSE']
    invalid_origin_response_api=ServerSettings['INVALID_ORIGIN_RESPONSE_API']
    invalid_csrf_token_response=ServerSettings['INVALID_CSRF_TOKEN_RESPONSE']
    invalid_csrf_token_response_api=ServerSettings['INVALID_CSRF_TOKEN_RESPONSE_API']
    invalid_jwt_token_response=ServerSettings['INVALID_JWT_TOKEN_RESPONSE']
    invalid_files_response=ServerSettings['INVALID_FILES_RESPONSE']
    invalid_files_response_api=ServerSettings['INVALID_FILES_RESPONSE_API']

    @staticmethod
    def get_jwt_token(token):
        try:
            data=JWTAuthenticationAPI.decode_token(token)
        except:
            return
        if (time.time() - data['jwt_token_created_at'] < JWTAuthenticationAPI.jwt_token_lifetime):
            return data
        return

    @staticmethod
    def validate_jwt_token():
        @functools.wraps(f)
        def validate(*args, **kwargs):
            try:
                token=request.headers.get(HeadersAPI.authorization_header,'').split()[-1]
            except:
                token=""
            if len(token)==0:
                return ValidatorsAPI.invalid_jwt_token_response,ValidatorsAPI.invalid_check_code
            try:
                d=ValidatorsAPI.get_jwt_token(token)
                SessionAPI.dump_jwt_data_into_session(session,d)
            except:
                return ValidatorsAPI.invalid_jwt_token_response,ValidatorsAPI.invalid_check_code
            return f(*args, **kwargs)
        return validate

    @staticmethod
    def validate_origin_header(obj,allowed_domains=[]):
        domains=[obj.host] if (not allowed_domains or len(allowed_domains)==0) else allowed_domains
        referer=obj.headers.get('Origin','')
        if referer.strip()=="" or referer.strip().lower()=="null":
            return False
        if '://' in referer:
            a=referer.split("://")[1].split("/")[0]
        else:
            a=referer.split('/')[0]
        if a not in domains:
            return False
        return True

    @staticmethod
    def user_is_authenticated(s):
        return time.time() - s.get('user_session',{}).get('user_logged_in_at',0) < ValidatorsAPI.user_session_lifetime

    @staticmethod
    def admin_is_authenticated(s):
        return time.time() - s.get('admin_session',{}).get('admin_logged_in_at',0) < ValidatorsAPI.admin_session_lifetime

    @staticmethod
    def admin_is_superadmin(s):
        return s.get('admin_session',{}).get('admin_is_super_admin',False)

    @staticmethod
    def superadmin_is_authenticated(s):
        return time.time() - s.get('admin_session',{}).get('admin_logged_in_at',0) < ValidatorsAPI.admin_session_lifetime and ValidatorsAPI.admin_is_superadmin(s)

    @staticmethod
    def editor_admin_is_authenticated(s):
        return time.time() - s.get('admin_session',{}).get('admin_logged_in_at',0) < ValidatorsAPI.admin_session_lifetime and ValidatorsAPI.admin_is_superadmin(s)==False

    @staticmethod
    def csrf_token_checker(r,s):
        return r.form.get(ValidatorsAPI.csrf_token_name,"")==s.get(ValidatorsAPI.csrf_token_name,"")

    @staticmethod
    def user_csrf_token_checker(r,s):
        return r.form.get(ValidatorsAPI.csrf_token_name,"")==s.get('user_session',{}).get(ValidatorsAPI.csrf_token_name,"")

    @staticmethod
    def csrf_referer_checker(req,allowed_domains=[]):
        return sanitizy.CSRF.validate_flask(req,allowed_domains=allowed_domains)

    @staticmethod
    def authenticated_admin(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.admin_is_authenticated(session)==True:
                return f(*args, **kwargs)
            else:
                return redirect(ValidatorsAPI.unauthenticated_admin_redirect)
        return validate

    @staticmethod
    def unauthenticated_admin(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.admin_is_authenticated(session)==False:
                return f(*args, **kwargs)
            else:
                return redirect(ValidatorsAPI.authenticated_admin_redirect)
        return validate

    @staticmethod
    def authenticated_user(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.user_is_authenticated(session)==True:
                return f(*args, **kwargs)
            else:
                return redirect(ValidatorsAPI.unauthenticated_user_redirect)
        return validate

    @staticmethod
    def unauthenticated_user(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.user_is_authenticated(session)==False:
                return f(*args, **kwargs)
            else:
                return redirect(ValidatorsAPI.authenticated_user_redirect)
        return validate

    @staticmethod
    def valid_authorization_flask_session(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            try:
                token=request.headers.get(HeadersAPI.authorization_header,'').split()[-1]
            except:
                token=""
            if len(token)==0:
                return ValidatorsAPI.invalid_flask_session_response,ValidatorsAPI.invalid_check_code
            try:
                d=FlaskSessionAPI.decode_flask_token(token)
                SessionAPI.set_session_variables(session,d)
            except:
                return ValidatorsAPI.invalid_flask_session_response_api,ValidatorsAPI.invalid_check_code
            return f(*args, **kwargs)
        return validate

    @staticmethod
    def valid_referer(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.csrf_referer_checker(request,allowed_domains=ValidatorsAPI.accepted_referer_domains)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_referer_response,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_referer_api(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.csrf_referer_checker(request,allowed_domains=ValidatorsAPI.accepted_referer_domains)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_referer_response_api,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_csrf_token(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.csrf_token_checker(request,session)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_csrf_token_response,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_csrf_token_api(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.csrf_token_checker(request,session)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_csrf_token_response_api,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_origin(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.validate_origin_header(request,allowed_domains=ValidatorsAPI.accepted_origin_domains)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_origin_response,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_origin_api(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if ValidatorsAPI.validate_origin_header(request,allowed_domains=ValidatorsAPI.accepted_origin_domains)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_origin_response_api,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_files(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if sanitizy.FILE_UPLOAD.validate_form(request,allowed_extensions=ValidatorsAPI.allowed_extensions,allowed_mimetypes=ValidatorsAPI.allowed_mimetypes)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_files_response,ValidatorsAPI.invalid_check_code
        return validate

    @staticmethod
    def valid_files_api(f):
        @functools.wraps(f)
        def validate(*args, **kwargs):
            if sanitizy.FILE_UPLOAD.validate_form(request,allowed_extensions=ValidatorsAPI.allowed_extensions,allowed_mimetypes=ValidatorsAPI.allowed_mimetypes)==True:
                return f(*args, **kwargs)
            else:
                return ValidatorsAPI.invalid_files_response_api,ValidatorsAPI.invalid_check_code
        return validate



app.jinja_env.globals.update(user_is_authenticated=ValidatorsAPI.user_is_authenticated)



#https://thepoints.medium.com/upload-data-to-firebase-cloud-firestore-with-10-line-of-python-code-1877690a55c6


class FirebaseAPI:

    firebase_apikey=ServerSettings['FIREBASE_APIKEY']
    firebase_storage_bucket=ServerSettings['FIREBASE_STORAGE_BUCKET']
    if firebase_storage_bucket!=None and firebase_storage_bucket.strip()!='':
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"]=ServerSettings['FIREBASE_CONFIG_FILE']
        FirebaseAdminApp = firebase_admin.initialize_app()
    import requests

    @staticmethod
    def delete_file(file_name):
        storage_client = GoogleCloudStorage.Client()
        bucket = storage_client.bucket(firebase_storage_bucket)
        bucket.delete_blob(file_name)

    @staticmethod
    def upload_file(f):
        storage_client = GoogleCloudStorage.Client()
        bucket = storage_client.bucket(firebase_storage_bucket)
        blob = bucket.blob(f.filename) 
        blob.upload_from_string(f.read())
        return blob.public_url

    @staticmethod
    def upload_all_files(fs):
        return [ FirebaseAPI.upload_to_firebase(x) for x in fs ]

#https://firebase.google.com/docs/auth/admin/manage-users?hl=en#python_6

    @staticmethod
    def create_user(**kwargs):
        return FirebaseAuthAPI.create_user(**kwargs).__dict__

    @staticmethod
    def fetch_user_by_id(uid):
        return FirebaseAuthAPI.get_user(uid).__dict__

    @staticmethod
    def fetch_user_by_email(email):
        return FirebaseAuthAPI.get_user_by_email(email).__dict__

    @staticmethod
    def fetch_user_by_phone(phone):
        return FirebaseAuthAPI.get_user_by_phone_number(phone).__dict__

    @staticmethod
    def list_users():
        return FirebaseAuthAPI.list_users().__dict__

    @staticmethod
    def list_all_emails():
        a=FirebaseAPI.list_users()
        return [ x['email'] for x in a['_current']['users'] ]
  

    @staticmethod
    def update_user(user_id, **kwargs):
        return FirebaseAuthAPI.update_user(user_id, **kwargs).__dict__

    @staticmethod
    def delete_user(uid):
        return FirebaseAuthAPI.delete_user(uid)

    @staticmethod
    def delete_users(*args):
        return FirebaseAuthAPI.delete_users(args)

#https://blog.icodes.tech/posts/python-firebase-authentication.html

#https://firebase.google.com/docs/database/admin/save-data?hl=en

    @staticmethod
    def signup(**kwargs):
        kwargs.update({'returnSecureToken': True})
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={}'.format(FirebaseAPI.firebase_apikey),data=kwargs)
            return json.loads(r.text)
        except:
            return {}

    @staticmethod
    def signin(email,password):
        details={'email':email,'password':password,'returnSecureToken': True}
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={}'.format(FirebaseAPI.firebase_apikey),data=details)
            return json.loads(r.text)
        except:
            return {}

    @staticmethod
    def verify_email(idToken):
        data={"requestType":"VERIFY_EMAIL","idToken":idToken}
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={}'.format(FirebaseAPI.firebase_apikey), data=data)
            return json.loads(r.text)
        except:
            return {}

    @staticmethod
    def reset_password(email):
        data={"requestType":"PASSWORD_RESET","email":email}
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={}'.format(FirebaseAPI.firebase_apikey), data=data)
            return json.loads(r.text)
        except:
            return {}

    @staticmethod
    def anonymous_signin():
        data={"returnSecureToken":"true"}
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={}'.format(FirebaseAPI.firebase_apikey), data=data)
            return json.loads(r.text)
        except:
            return {}
  
    @staticmethod
    def user_data(idToken):
        details={'idToken':idToken}
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={}'.format(FirebaseAPI.firebase_apikey), data=details)
            return json.loads(r.text)
        except:
            return {}

    @staticmethod
    def delete_account(idToken):
        data={"idToken":idToken}
        try:
            r=FirebaseAPI.requests.post('https://identitytoolkit.googleapis.com/v1/accounts:delete?key={}'.format(FirebaseAPI.firebase_apikey), data=data)
            return json.loads(r.text)
        except:
            return {}





class MongoDbQueriesAPI:

    def __init__(self,collection):
        self.db=db_mongo
        self.collection=self.db[collection]  

    def read_one(self,condition):
        try:
            return dict(self.collection.find_one(condition))
        except Exception as ex:
            print(ex)

    def read_many(self,condition):
        l=self.collection.find({},condition)
        try:
            return list(l)
        except:
            pass

    def read_all(self,condition=None):
        l=self.collection.find(condition)
        try:
            return list(l)
        except:
            pass

    def insert_one(self,data):
        return self.collection.insert_one(data).inserted_id.__str__()
  
    def insert_many(self,data):
        l= self.collection.insert_many(data).inserted_ids
        return [ x.__str__() for x in l]
  
    def update_one(self,old_data,new_data):
        return self.collection.update_one(old_data, {"$set": new_data})
  
    def update_many(self,old_data,new_data):
        return self.collection.update_one(old_data, {"$set": new_data}).modified_count
 
    def delete_one(self,data):
        return self.collection.delete_one(data)
  
    def delete_many(self,data):
        return self.collection.delete_many(data).deleted_count

    def close(self):
        self.connection=None
        self.db=None
        self.collection=None
        self.connection_uri=None
  







class MongoDbAPI:

    @staticmethod
    def mongo_read_one(collection,condition):
        a=MongoDbQueriesAPI(collection)
        x=a.read_one(condition)
        a.close()
        return x

    @staticmethod
    def mongo_read_many(collection,condition):
        a=MongoDbQueriesAPI(collection)
        x=a.read_many(condition)
        a.close()
        return x

    @staticmethod
    def mongo_read_all(collection):
        a=MongoDbQueriesAPI(collection)
        x=a.read_all()
        a.close()
        return x

    @staticmethod
    def mongo_insert_one(collection,data):
        a=MongoDbQueriesAPI(collection)
        x=a.insert_one(data)
        a.close()
        return x

    @staticmethod
    def mongo_insert_many(collection,data):
        a=MongoDbQueriesAPI(collection)
        x=a.insert_many(data)
        a.close()
        return x

    @staticmethod
    def mongo_update_one(collection,old_data,new_data):
        a=MongoDbQueriesAPI(collection)
        x=a.update_one(old_data,new_data)
        a.close()
        return x

    @staticmethod
    def mongo_update_many(collection,old_data,new_data):
        a=MongoDbQueriesAPI(collection)
        x=a.update_many(old_data,new_data)
        a.close()
        return x

    @staticmethod
    def mongo_delete_one(collection,data):
        a=MongoDbQueriesAPI(collection)
        x=a.delete_one(data)
        a.close()
        return x

    @staticmethod
    def mongo_delete_many(collection,data):
        a=MongoDbQueriesAPI(collection)
        x=a.delete_many(data)
        a.close()
        return x






class AdminDashboardView(flask_admin.AdminIndexView):

    def is_visible(self):
        # This view won't appear in the menu structure
        return False

    def is_accessible(self):
        if request.method!='GET':
            return sanitizy.CSRF.validate_flask(request) 
        return True

    # exposing the login and lougout interfaces and adding the login and logout processes to the default flask_admin interface

    def inaccessible_callback(self, name, **kwargs):
        if request.path.startswith(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)==False:
            return flask.abort(401)
        # redirect to login page if user doesn't have access
        return redirect(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH)




class FlaskAdminModelView(FlaskAdminModelView):
    can_create=True
    can_delete=True
    can_edit=True
    can_read=True
    form_base_class = SecureModelForm



class Admins(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_avatar=db.Column(db.String(500),nullable=True, default='/static/admins/default_admin_avatar.jpg')
    username=db.Column(db.String(50), unique=True, nullable=False)
    full_name=db.Column(db.String(50), nullable=False)
    phone=db.Column(db.String(16))
    email=db.Column(db.String(50), unique=True, nullable=False)
    password=db.Column(db.String(120), nullable=False)
    super_admin = db.Column(db.Boolean, default=False, nullable=False)
    active = db.Column(db.Boolean, default=False)
    created_at = sqlalchemy.Column(sqlalchemy.TIMESTAMP , server_default=sqlalchemy.sql.func.now())
    last_login_at = sqlalchemy.Column(sqlalchemy.TIMESTAMP , server_default=sqlalchemy.sql.func.now())
    def __repr__(self):
        return self.username








# this class will inherit from the class "AdminIndexView" of "flask_admin" module and we will add some new methods and edit some others
class AdminDashboardView(flask_admin.AdminIndexView):

    @flask_admin.expose('/', methods=('GET', 'POST'))
    def index(self):
        if request.path.startswith(AdminDashboardSettingsBaseURL.ADMIN_PANEL_BASE_URL)==False:
            return flask.abort(401)
        return self.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_INDEX_TEMPLATE)

    def is_visible(self):
        # This view won't appear in the menu structure
        return False

    def is_accessible(self):
        if request.method!='GET':
            return sanitizy.CSRF.validate_flask(request) 
        return True

    # exposing the login and lougout interfaces and adding the login and logout processes to the default flask_admin interface

    def inaccessible_callback(self, name, **kwargs):
        if request.path.startswith(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)==False:
            return flask.abort(401)
        # redirect to login page if user doesn't have access
        return redirect(request.headers.get('referer',AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH))





class AdminDashbordModelView(FlaskAdminModelView):
    DEFAULT_ADMIN_UPLOAD_FOLDER=ServerSettings['DEFAULT_ADMIN_UPLOAD_FOLDER']
    DEFAULT_ADMIN_UPLOAD_PATH='/'+ServerSettings['DEFAULT_ADMIN_UPLOAD_FOLDER']
    MODEL_NAME=''
    MODEL_STORAGE='local'
    can_create=True
    can_delete=True
    can_edit=True
    can_read=True
    form_base_class = SecureModelForm

    @flask_admin.expose('/new/', methods=('GET', 'POST'))
    def create_view(self):
        '''
            Create model view
        '''
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_create:
            return redirect(return_url)

        form = self.create_form()
        if not hasattr(form, '_validated_ruleset') or not form._validated_ruleset:
            self._validate_form_instance(ruleset=self._form_create_rules, form=form)

        if self.validate_form(form):
            # in versions 1.1.0 and before, this returns a boolean
            # in later versions, this is the model itself
            self.save_files()
            for x in form.__dict__['_fields']:
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            model = self.create_model(form)
            if model:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record was successfully created.')), 'success')
                if '_add_another' in request.form:
                    return redirect(request.url)
                elif '_continue_editing' in request.form:
                    # if we have a valid model, try to go to the edit view
                    if model is not True:
                        url = self.get_url('.edit_view', id=self.get_pk_value(model), url=return_url)
                    else:
                        url = return_url
                    return redirect(url)
                else:
                    # save button
                    return redirect(self.get_save_return_url(model, is_created=True))

        form_opts = FormOpts(widget_args=self.form_widget_args,
                             form_rules=self._form_create_rules)

        if self.create_modal and request.args.get('modal'):
            template = self.create_modal_template
        else:
            template = self.create_template

        return self.render(template,
                           form=form,
                           form_opts=form_opts,
                           return_url=return_url)

    @flask_admin.expose('/edit/',methods=['GET','POST'])
    def edit_view(self):
        '''
            Edit model view
        '''
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_edit:
            return redirect(return_url)

        id = get_mdict_item_or_list(request.args, 'id')
        if id is None:
            return redirect(return_url)

        model = self.get_one(id)

        if model is None:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record does not exist.')), 'error')
            return redirect(return_url)

        form = self.edit_form(obj=model)
        if not hasattr(form, '_validated_ruleset') or not form._validated_ruleset:
            self._validate_form_instance(ruleset=self._form_edit_rules, form=form)

        if self.validate_form(form):
            self.save_files()
            for x in form.__dict__['_fields']:
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            if self.update_model(form, model):
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record was successfully saved.')), 'success')
                if '_add_another' in request.form:
                    return redirect(self.get_url('.create_view', url=return_url))
                elif '_continue_editing' in request.form:
                    return redirect(self.get_url('.edit_view', id=self.get_pk_value(model)))
                else:
                    # save button
                    return redirect(self.get_save_return_url(model, is_created=False))

        if request.method == 'GET' or form.errors:
            self.on_form_prefill(form, id)

        form_opts = FormOpts(widget_args=self.form_widget_args,
                             form_rules=self._form_edit_rules)

        if self.edit_modal and request.args.get('modal'):
            template = self.edit_modal_template
        else:
            template = self.edit_template

        return self.render(template,
                           model=model,
                           form=form,
                           form_opts=form_opts,
                           return_url=return_url)

    @flask_admin.expose('/details/',methods=['GET','POST'])
    def details_view(self):
        '''
            Details model view
        '''
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_view_details:
            return redirect(return_url)

        id = get_mdict_item_or_list(request.args, 'id')
        if id is None:
            return redirect(return_url)

        model = self.get_one(id)

        if model is None:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record does not exist.')), 'error')
            return redirect(return_url)

        if self.details_modal and request.args.get('modal'):
            template = self.details_modal_template
        else:
            template = self.details_template

        return self.render(template,
                           model=model,
                           details_columns=self._details_columns,
                           get_value=self.get_detail_value,
                           return_url=return_url)

    @flask_admin.expose('/delete/', methods=('POST',))
    def delete_view(self):
        '''
            Delete model view. Only POST method is allowed.
        '''
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_delete:
            return redirect(return_url)

        form = self.delete_form()

        if self.validate_form(form):
            # id is InputRequired()
            id = form.id.data

            model = self.get_one(id)

            if model is None:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record does not exist.')), 'error')
                return redirect(return_url)

            # message is flashed from within delete_model if it fails
            if self.delete_model(model):
                count = 1
                flask.flash(
                    flask_admin.babel.ngettext(TranslateInTemplate.TranslateWord_Admin(session,'Record was successfully deleted.'),
                             '%(count)s '+TranslateInTemplate.TranslateWord_Admin(session,'records were successfully deleted.'),
                             count, count=count), 'success')
                return redirect(return_url)
        else:
            flash_errors(form, message=TranslateInTemplate.TranslateWord_Admin(session,'Failed to delete record.')+' %(error)s')

        return redirect(return_url)

    @flask_admin.expose('/action/', methods=('POST',))
    def action_view(self):
        '''
            Mass-model action view.
        '''
        return self.handle_action()

    def _export_data(self):
        # Macros in column_formatters are not supported.
        # Macros will have a function name 'inner'
        # This causes non-macro functions named 'inner' not work.
        for col, func in iteritems(self.column_formatters_export):
            # skip checking columns not being exported
            if col not in [col for col, _ in self._export_columns]:
                continue

            if func.__name__ == 'inner':
                raise NotImplementedError(
                    TranslateInTemplate.TranslateWord_Admin(session,'Macros are not implemented in export. Exclude column in'
                    ' column_formatters_export, column_export_list, or '
                    ' column_export_exclude_list. Column:')+' %s' % (col,)
                )

        # Grab parameters from URL
        view_args = self._get_list_extra_args()

        # Map column index to column name
        sort_column = self._get_column_by_idx(view_args.sort)
        if sort_column is not None:
            sort_column = sort_column[0]

        # Get count and data
        count, data = self.get_list(0, sort_column, view_args.sort_desc,
                                    view_args.search, view_args.filters,
                                    page_size=self.export_max_rows)

        return count, data

    @flask_admin.expose('/export/<export_type>/')
    def export(self, export_type):
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_export or (export_type not in self.export_types):
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Permission denied.')), 'error')
            return redirect(return_url)

        if export_type == 'csv':
            return self._export_csv(return_url)
        else:
            return self._export_tablib(export_type, return_url)

    def _export_csv(self, return_url):
        '''
            Export a CSV of records as a stream.
        '''
        count, data = self._export_data()

        # https://docs.djangoproject.com/en/1.8/howto/outputting-csv/
        class Echo(object):
            '''
            An object that implements just the write method of the file-like
            interface.
            '''
            def write(self, value):
                '''
                Write the value by returning it, instead of storing
                in a buffer.
                '''
                return value

        writer = csv.writer(Echo())

        def generate():
            # Append the column titles at the beginning
            titles = [csv_encode(c[1]) for c in self._export_columns]
            yield writer.writerow(titles)

            for row in data:
                vals = [csv_encode(self.get_export_value(row, c[0]))
                        for c in self._export_columns]
                yield writer.writerow(vals)

        filename = self.get_export_name(export_type='csv')

        disposition = 'attachment;filename=%s' % (secure_filename(filename),)

        return Response(
            stream_with_context(generate()),
            headers={'Content-Disposition': disposition},
            mimetype='text/csv'
        )

    def _export_tablib(self, export_type, return_url):
        '''
            Exports a variety of formats using the tablib library.
        '''
        if tablib is None:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Tablib dependency not installed.')), 'error')
            return redirect(return_url)

        filename = self.get_export_name(export_type)

        disposition = 'attachment;filename=%s' % (secure_filename(filename),)

        mimetype, encoding = mimetypes.guess_type(filename)
        if not mimetype:
            mimetype = 'application/octet-stream'
        if encoding:
            mimetype = '%s; charset=%s' % (mimetype, encoding)

        ds = tablib.Dataset(headers=[csv_encode(c[1]) for c in self._export_columns])

        count, data = self._export_data()

        for row in data:
            vals = [csv_encode(self.get_export_value(row, c[0])) for c in self._export_columns]
            ds.append(vals)

        try:
            try:
                response_data = ds.export(format=export_type)
            except AttributeError:
                response_data = getattr(ds, export_type)
        except (AttributeError, tablib.UnsupportedFormat):
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Export type ')+'"%(type)s'+TranslateInTemplate.TranslateWord_Admin(session,' not supported.'),
                          type=export_type), 'error')
            return redirect(return_url)

        return Response(
            response_data,
            headers={'Content-Disposition': disposition},
            mimetype=mimetype,
        )

    @flask_admin.expose('/ajax/lookup/')
    def ajax_lookup(self):
        name = request.args.get('name')
        query = request.args.get('query')
        offset = request.args.get('offset', type=int)
        limit = request.args.get('limit', 10, type=int)

        loader = self._form_ajax_refs.get(name)

        if not loader:
            abort(404)

        data = [loader.format(m) for m in loader.get_list(query, offset, limit)]
        return Response(json.dumps(data), mimetype='application/json')

    @flask_admin.expose('/ajax/update/', methods=('POST',))
    def ajax_update(self):
        '''
            Edits a single column of a record in list view.
        '''
        if not self.column_editable_list:
            abort(404)

        form = self.list_form()

        # prevent validation issues due to submitting a single field
        # delete all fields except the submitted fields and csrf token
        for field in list(form):
            if (field.name in request.form) or (field.name == 'csrf_token'):
                pass
            else:
                form.__delitem__(field.name)

        if self.validate_form(form):
            self.save_files()
            for x in form.__dict__['_fields']:
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            pk = form.list_form_pk.data
            record = self.get_one(pk)

            if record is None:
                return flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record does not exist.')), 500

            if self.update_model(form, record):
                # Success
                return flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Record was successfully saved.'))
            else:
                # Error: No records changed, or problem saving to database.
                msgs = ", ".join([msg for msg in get_flashed_messages()])
                return flask_admin.babel.gettext('Failed to update record. %(error)s',
                               error=msgs), 500
        else:
            for field in form:
                for error in field.errors:
                    # return validation error to x-editable
                    if isinstance(error, list):
                        return flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to update record.')+' %(error)s',
                                       error=", ".join(error)), 500
                    else:
                        return flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to update record.')+' %(error)s',
                                       error=error), 500


    def save_files(self):
        if request.method!='GET' and len(request.files)>0:
            d={}
            for x in request.files:
                if request.files[x].filename!='':
                    try:
                        if self.MODEL_STORAGE=='s3':
                            d.update({x:Amazon_S3_API.save_file(request.files[x])})
                        elif self.MODEL_STORAGE=='firebase':
                            d.update({x:'/'+FirebaseAPI.upload_file(request.files[x])})
                        else:
                            d.update({x:'/'+FileManagerAPI.save_file(request.files[x],path=self.DEFAULT_ADMIN_UPLOAD_FOLDER+'/'+self.MODEL_NAME).replace('\\','/')})
                    
                    except Exception as ex:
                        print(ex)
                else:
                    d.update({x:''})
            request.files=werkzeug.datastructures.ImmutableMultiDict(d)

    def is_accessible(self):
        if request.method=='GET':
            return ValidatorsAPI.admin_is_authenticated(session)
        else:
            self.save_files()
            return sanitizy.CSRF.validate_flask(request) and ValidatorsAPI.admin_is_authenticated(session) and AdminDashboardSettings.READ_ONLY_MODE==False

    def inaccessible_callback(self, name, **kwargs):
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            if request.headers.get('referer','').strip()=='' or request.headers.get('referer','').startswith(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)==False:
                return flask.abort(401)
            return redirect(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH)
        return redirect(request.headers.get('referer',AdminDashboardSettings.ADMIN_PANEL_BASE_URL))



class AdminDashbordModelViewEditor(AdminDashbordModelView):

    def is_accessible(self):
        if request.method=='GET':
            return ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==False
        else:
            return sanitizy.CSRF.validate_flask(request) and ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==False and AdminDashboardSettings.READ_ONLY_MODE==False

    def is_visible(self):
        if self.can_read==False or (self.can_read==False and len(set([self.can_read,self.can_edit,self.can_delete,self.can_create])) <= 1):
            return False
        return ValidatorsAPI.superadmin_is_authenticated(session)==False




class AdminDashbordModelViewAdmin(AdminDashbordModelView):

    can_export=True

    def is_accessible(self):
        if request.method=='GET':
            return ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==True
        else:
            return sanitizy.CSRF.validate_flask(request) and ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==True and AdminDashboardSettings.READ_ONLY_MODE==False

    def is_visible(self):
        if self.can_read==False or (self.can_read==False and len(set([self.can_read,self.can_edit,self.can_delete,self.can_create])) <= 1):
            return False
        return  ValidatorsAPI.superadmin_is_authenticated(session)



class MongodbAdminModelView(flask_admin.model.BaseModelView):
    can_read=True
    can_delete=True
    can_edit=True
    can_create=True
    can_export=True



class AdminDashbordModelViewEditorMongodb(MongodbAdminModelView):

    column_filters = None
    DEFAULT_ADMIN_UPLOAD_FOLDER=ServerSettings['DEFAULT_ADMIN_UPLOAD_FOLDER']
    DEFAULT_ADMIN_UPLOAD_PATH='/'+ServerSettings['DEFAULT_ADMIN_UPLOAD_FOLDER']
    MODEL_NAME=''
    MODEL_STORAGE='local'
    
    def __init__(self, coll,
                 name=None, category=None, endpoint=None, url=None,
                 menu_class_name=None, menu_icon_type=None, menu_icon_value=None):
        self._search_fields = []

        if name is None:
            name = self._prettify_name(coll.name)

        if endpoint is None:
            endpoint = ('%sview' % coll.name).lower()

        super(MongodbAdminModelView, self).__init__(None, name, category, endpoint, url,
                                        menu_class_name=menu_class_name,
                                        menu_icon_type=menu_icon_type,
                                        menu_icon_value=menu_icon_value)

        self.coll = coll

    def scaffold_pk(self):
        return '_id'

    def get_pk_value(self, model):
        return model.get('_id')

    def scaffold_list_columns(self):
        raise NotImplementedError()

    def scaffold_sortable_columns(self):
        return []

    def init_search(self):
        if self.column_searchable_list:
            for p in self.column_searchable_list:
                if not isinstance(p, string_types):
                    raise ValueError('Expected string')

                # TODO: Validation?

                self._search_fields.append(p)

        return bool(self._search_fields)

    def scaffold_filters(self, attr):
        raise NotImplementedError()

    def is_valid_filter(self, filter):
        return isinstance(filter, BasePyMongoFilter)

    def scaffold_form(self):
        raise NotImplementedError()

    def _get_field_value(self, model, name):
        return model.get(name)

    def _search(self, query, search_term):
        values = search_term.split(' ')

        queries = []

        # Construct inner querie
        for value in values:
            if not value:
                continue

            regex = parse_like_term(value)

            stmt = []
            for field in self._search_fields:
                stmt.append({field: {'$regex': regex}})

            if stmt:
                if len(stmt) == 1:
                    queries.append(stmt[0])
                else:
                    queries.append({'$or': stmt})

        # Construct final query
        if queries:
            if len(queries) == 1:
                final = queries[0]
            else:
                final = {'$and': queries}

            if query:
                query = {'$and': [query, final]}
            else:
                query = final

        return query

    def get_list(self, page, sort_column, sort_desc, search, filters,
                 execute=True, page_size=None):
        query = {}

        # Filters
        if self._filters:
            data = []

            for flt, flt_name, value in filters:
                f = self._filters[flt]
                data = f.apply(data, f.clean(value))

            if data:
                if len(data) == 1:
                    query = data[0]
                else:
                    query['$and'] = data

        # Search
        if self._search_supported and search:
            query = self._search(query, search)

        # Get count
        count = self.coll.count_documents(query) if not self.simple_list_pager else None

        # Sorting
        sort_by = None

        if sort_column:
            sort_by = [(sort_column, pymongo.DESCENDING if sort_desc else pymongo.ASCENDING)]
        else:
            order = self._get_default_order()

            if order:
                sort_by = [(col, pymongo.DESCENDING if desc else pymongo.ASCENDING)
                           for (col, desc) in order]

        # Pagination
        if page_size is None:
            page_size = self.page_size

        skip = 0

        if page and page_size:
            skip = page * page_size

        results = self.coll.find(query, sort=sort_by, skip=skip, limit=page_size)

        if execute:
            results = list(results)

        return count, results

    def _get_valid_id(self, id):
        try:
            return ObjectId(id)
        except InvalidId:
            return id

    def get_one(self, id):
        return self.coll.find_one({'_id': self._get_valid_id(id)})

    def edit_form(self, obj):
        return self._edit_form_class(get_form_data(), **obj)

    def create_model(self, form):
        try:
            self.save_files()
            for x in form.__dict__['_fields']:
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            model = form.data
            self._on_model_change(form, model, True)
            self.coll.insert_one(model)
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to create record. %(error)s'), error=str(ex)),
                  'error')
            log.exception('Failed to create record.')
            return False
        else:
            self.after_model_change(form, model, True)

        return model

    def update_model(self, form, model):
        try:
            self.save_files()
            for x in form.__dict__['_fields']:
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            model.update(form.data)
            self._on_model_change(form, model, False)

            pk = self.get_pk_value(model)
            self.coll.replace_one({'_id': pk}, model)
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to update record.')+' %(error)s', error=str(ex)),
                  'error')
            log.exception('Failed to update record.')
            return False
        else:
            self.after_model_change(form, model, False)

        return True

    def delete_model(self, model):
        try:
            pk = self.get_pk_value(model)

            if not pk:
                raise ValueError('Document does not have _id')

            self.on_model_delete(model)
            self.coll.delete_one({'_id': pk})
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to delete record.')+' %(error)s', error=str(ex)),
                  'error')
            log.exception('Failed to delete record.')
            return False
        else:
            self.after_model_delete(model)

        return True

    # Default model actions
    def is_action_allowed(self, name):
        # Check delete action permission
        if name == 'delete' and not self.can_delete:
            return False

        return super(MongodbAdminModelView, self).is_action_allowed(name)

    @action('delete',
            flask_admin.babel.lazy_gettext('Delete'),
            flask_admin.babel.lazy_gettext('Are you sure you want to delete selected records?'))
    def action_delete(self, ids):
        try:
            count = 0

            # TODO: Optimize me
            for pk in ids:
                if self.delete_model(self.get_one(pk)):
                    count += 1

            flask.flash(flask_admin.babel.ngettext(TranslateInTemplate.TranslateWord_Admin(session,'Record was successfully deleted.'),
                           '%(count)s '+TranslateInTemplate.TranslateWord_Admin(session,'records were successfully deleted.'),
                           count,
                           count=count), 'success')
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext('Failed to delete records. %(error)s', error=str(ex)), 'error')

    def save_files(self):
        if request.method!='GET' and len(request.files)>0:
            d={}
            for x in request.files:
                if request.files[x].filename!='':
                    try:
                        if self.MODEL_STORAGE=='s3':
                            d.update({x:Amazon_S3_API.save_file(request.files[x])})
                        elif self.MODEL_STORAGE=='firebase':
                            d.update({x:'/'+FirebaseAPI.upload_file(request.files[x])})
                        else:
                            d.update({x:'/'+FileManagerAPI.save_file(request.files[x],path=self.DEFAULT_ADMIN_UPLOAD_FOLDER+'/'+self.MODEL_NAME).replace('\\','/')})
                    
                    except Exception as ex:
                        print(ex)
                else:
                    d.update({x:''})
            request.files=werkzeug.datastructures.ImmutableMultiDict(d)

    def inaccessible_callback(self, name, **kwargs):
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            if request.headers.get('referer','').strip()=='' or request.headers.get('referer','').startswith(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)==False:
                return flask.abort(401)
            return redirect(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH)
        return redirect(request.headers.get('referer',AdminDashboardSettings.ADMIN_PANEL_BASE_URL))
    def is_accessible(self):
        if request.method=='GET':
            return ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==False
        else:
            return sanitizy.CSRF.validate_flask(request) and ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==False and AdminDashboardSettings.READ_ONLY_MODE==False

    def is_visible(self):
        if self.can_read==False or (self.can_read==False and len(set([self.can_read,self.can_edit,self.can_delete,self.can_create])) <= 1):
            return False
        return ValidatorsAPI.superadmin_is_authenticated(session)==False




class AdminDashbordModelViewAdminMongodb(MongodbAdminModelView):

    column_filters = None
    DEFAULT_ADMIN_UPLOAD_FOLDER=ServerSettings['DEFAULT_ADMIN_UPLOAD_FOLDER']
    DEFAULT_ADMIN_UPLOAD_PATH='/'+ServerSettings['DEFAULT_ADMIN_UPLOAD_FOLDER']
    MODEL_NAME=''
    MODEL_STORAGE='local'
    
    def __init__(self, coll,
                 name=None, category=None, endpoint=None, url=None,
                 menu_class_name=None, menu_icon_type=None, menu_icon_value=None):
        self._search_fields = []

        if name is None:
            name = self._prettify_name(coll.name)

        if endpoint is None:
            endpoint = ('%sview' % coll.name).lower()

        super(MongodbAdminModelView, self).__init__(None, name, category, endpoint, url,
                                        menu_class_name=menu_class_name,
                                        menu_icon_type=menu_icon_type,
                                        menu_icon_value=menu_icon_value)

        self.coll = coll

    def scaffold_pk(self):
        return '_id'

    def get_pk_value(self, model):
        return model.get('_id')

    def scaffold_list_columns(self):
        raise NotImplementedError()

    def scaffold_sortable_columns(self):
        return []

    def init_search(self):
        if self.column_searchable_list:
            for p in self.column_searchable_list:
                if not isinstance(p, string_types):
                    raise ValueError('Expected string')

                # TODO: Validation?

                self._search_fields.append(p)

        return bool(self._search_fields)

    def scaffold_filters(self, attr):
        raise NotImplementedError()

    def is_valid_filter(self, filter):
        return isinstance(filter, BasePyMongoFilter)

    def scaffold_form(self):
        raise NotImplementedError()

    def _get_field_value(self, model, name):
        return model.get(name)

    def _search(self, query, search_term):
        values = search_term.split(' ')

        queries = []

        # Construct inner querie
        for value in values:
            if not value:
                continue

            regex = parse_like_term(value)

            stmt = []
            for field in self._search_fields:
                stmt.append({field: {'$regex': regex}})

            if stmt:
                if len(stmt) == 1:
                    queries.append(stmt[0])
                else:
                    queries.append({'$or': stmt})

        # Construct final query
        if queries:
            if len(queries) == 1:
                final = queries[0]
            else:
                final = {'$and': queries}

            if query:
                query = {'$and': [query, final]}
            else:
                query = final

        return query

    def get_list(self, page, sort_column, sort_desc, search, filters,
                 execute=True, page_size=None):
        query = {}

        # Filters
        if self._filters:
            data = []

            for flt, flt_name, value in filters:
                f = self._filters[flt]
                data = f.apply(data, f.clean(value))

            if data:
                if len(data) == 1:
                    query = data[0]
                else:
                    query['$and'] = data

        # Search
        if self._search_supported and search:
            query = self._search(query, search)

        # Get count
        count = self.coll.count_documents(query) if not self.simple_list_pager else None

        # Sorting
        sort_by = None

        if sort_column:
            sort_by = [(sort_column, pymongo.DESCENDING if sort_desc else pymongo.ASCENDING)]
        else:
            order = self._get_default_order()

            if order:
                sort_by = [(col, pymongo.DESCENDING if desc else pymongo.ASCENDING)
                           for (col, desc) in order]

        # Pagination
        if page_size is None:
            page_size = self.page_size

        skip = 0

        if page and page_size:
            skip = page * page_size

        results = self.coll.find(query, sort=sort_by, skip=skip, limit=page_size)

        if execute:
            results = list(results)

        return count, results

    def _get_valid_id(self, id):
        try:
            return ObjectId(id)
        except InvalidId:
            return id

    def get_one(self, id):
        return self.coll.find_one({'_id': self._get_valid_id(id)})

    def edit_form(self, obj):
        return self._edit_form_class(get_form_data(), **obj)

    def create_model(self, form):
        try:
            self.save_files()
            for x in form.__dict__['_fields']:
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            model = form.data
            self._on_model_change(form, model, True)
            self.coll.insert_one(model)
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to create record.')+' %(error)s', error=str(ex)),
                  'error')
            log.exception('Failed to create record.')
            return False
        else:
            self.after_model_change(form, model, True)

        return model

    def update_model(self, form, model):
        try:
            self.save_files()
            for x in form.__dict__['_fields']:
                print(form.__dict__['_fields'][x].__dict__['data'])
                if form.__dict__['_fields'][x].__dict__['type']=='FileField':
                    form.__dict__['_fields'][x].__dict__['data']=request.files[x]
            model.update(form.data)
            self._on_model_change(form, model, False)

            pk = self.get_pk_value(model)
            self.coll.replace_one({'_id': pk}, model)
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to update record.')+' %(error)s', error=str(ex)),
                  'error')
            log.exception('Failed to update record.')
            return False
        else:
            self.after_model_change(form, model, False)

        return True

    def delete_model(self, model):
        try:
            pk = self.get_pk_value(model)

            if not pk:
                raise ValueError('Document does not have _id')

            self.on_model_delete(model)
            self.coll.delete_one({'_id': pk})
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Failed to delete record.')+' %(error)s', error=str(ex)),
                  'error')
            log.exception('Failed to delete record.')
            return False
        else:
            self.after_model_delete(model)

        return True

    # Default model actions
    def is_action_allowed(self, name):
        # Check delete action permission
        if name == 'delete' and not self.can_delete:
            return False

        return super(MongodbAdminModelView, self).is_action_allowed(name)

    @action('delete',
            flask_admin.babel.lazy_gettext('Delete'),
            flask_admin.babel.lazy_gettext('Are you sure you want to delete selected records?'))
    def action_delete(self, ids):
        try:
            count = 0

            # TODO: Optimize me
            for pk in ids:
                if self.delete_model(self.get_one(pk)):
                    count += 1

            flask.flash(flask_admin.babel.ngettext(TranslateInTemplate.TranslateWord_Admin(session,'Record was successfully deleted.'),
                           '%(count)s '+TranslateInTemplate.TranslateWord_Admin(session,'records were successfully deleted.'),
                           count,
                           count=count), 'success')
        except Exception as ex:
            flask.flash(flask_admin.babel.gettext('Failed to delete records. %(error)s', error=str(ex)), 'error')

    def save_files(self):
        if request.method!='GET' and len(request.files)>0:
            d={}
            for x in request.files:
                if request.files[x].filename!='':
                    try:
                        if self.MODEL_STORAGE=='s3':
                            d.update({x:Amazon_S3_API.save_file(request.files[x])})
                        elif self.MODEL_STORAGE=='firebase':
                            d.update({x:'/'+FirebaseAPI.upload_file(request.files[x])})
                        else:
                            d.update({x:'/'+FileManagerAPI.save_file(request.files[x],path=self.DEFAULT_ADMIN_UPLOAD_FOLDER+'/'+self.MODEL_NAME).replace('\\','/')})
                    
                    except Exception as ex:
                        print(ex)
                else:
                    d.update({x:''})
            request.files=werkzeug.datastructures.ImmutableMultiDict(d)

    def inaccessible_callback(self, name, **kwargs):
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            if request.headers.get('referer','').strip()=='' or request.headers.get('referer','').startswith(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)==False:
                return flask.abort(401)
            return redirect(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH)
        return redirect(request.headers.get('referer',AdminDashboardSettings.ADMIN_PANEL_BASE_URL))


    def is_accessible(self):
        if request.method=='GET':
            return ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==True
        else:
            return sanitizy.CSRF.validate_flask(request) and ValidatorsAPI.admin_is_authenticated(session) and ValidatorsAPI.admin_is_superadmin(session)==True and AdminDashboardSettings.READ_ONLY_MODE==False

    def is_visible(self):
        if self.can_read==False or (self.can_read==False and len(set([self.can_read,self.can_edit,self.can_delete,self.can_create])) <= 1):
            return False
        return  ValidatorsAPI.superadmin_is_authenticated(session)







class AdminsViewAdmin(AdminDashbordModelViewAdmin):

    def _list_thumbnail(view, context, model, name):
        if not model.admin_avatar:
            return ''

        return jinja2.Markup('<img src="%s" width="%s" height="%s">' % (model.admin_avatar,AdminDashboardSettings.ADMIN_AVATAR_WIDTH,AdminDashboardSettings.ADMIN_AVATAR_HEIGHT))
    column_formatters = {
    'admin_avatar': _list_thumbnail
    }
    form_excluded_columns = ('admin_avatar')
    """form_extra_fields = {
        'admin_avatar': FileField()
    }"""
    DEFAULT_ADMIN_UPLOAD_FOLDER="static/admins/avatars"


class AdminsViewEditor(AdminDashbordModelViewEditor):

    def _list_thumbnail(view, context, model, name):
        if not model.admin_avatar:
            return ''

        return jinja2.Markup('<img src="%s" width="%s" height="%s">' % (model.admin_avatar,AdminDashboardSettings.ADMIN_AVATAR_WIDTH,AdminDashboardSettings.ADMIN_AVATAR_HEIGHT))
    column_formatters = {
    'admin_avatar': _list_thumbnail
    }
    form_excluded_columns = ('admin_avatar')
    form_extra_fields = {
        'admin_avatar': FileField()
    }






class NormalMenuLink(flask_admin.menu.MenuLink):
    pass



class AuthenticatedMenuLink(flask_admin.menu.MenuLink):

    def is_accessible(self):
        return ValidatorsAPI.admin_is_authenticated(session)

    

# the login link only visible when the user is not looged in

class UnauthenticatedMenuLink(flask_admin.menu.MenuLink):

    def is_accessible(self):
        return ValidatorsAPI.admin_is_authenticated(session)==False


class SuperAdminMenuLink(flask_admin.menu.MenuLink):

    def is_accessible(self):
        return ValidatorsAPI.admin_is_authenticated(session)==True and ValidatorsAPI.admin_is_superadmin(session)==True



class EditorAdminMenuLink(flask_admin.menu.MenuLink):

    def is_accessible(self):
        return ValidatorsAPI.admin_is_authenticated(session)==True and ValidatorsAPI.admin_is_superadmin(session)==False


AdminDashboardViewInstance=AdminDashboardView(**AdminDashboardSettings.ADMINDASHBOARDVIEW_SETTINGS)

AdminDashboardApp = flask_admin.Admin(app, index_view=AdminDashboardViewInstance,**AdminDashboardSettings.ADMIN_APP_SETTINGS)


if AdminDashboardSettings.ADMIN_PANEL_ENABLED==True:
# adding all the models to the admin's interface to create their CRUD automatically with "flask_admin"
    AdminDashboardApp.add_view(AdminsViewAdmin(Admins, db.session,endpoint='Admins_Admin', name='Admins'))
    #AdminDashboardApp.add_view(AdminsViewEditor(Admins, db.session,endpoint='Admins_Editor',name='Admins'))
    
    
    @app.route(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH,methods=['GET','POST'])
    def admin_panel_function_login():
        if ValidatorsAPI.admin_is_authenticated(session)==True:
            return redirect(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)
        if request.method=='POST':
            if AdminDashboardSettings.ADMIN_PANEL_RECAPTCHA_ENABLED==True:
                if not GoogleReCaptchaAPI.recaptcha_app.verify():
                    SessionAPI.end_admin_session(session)
                    flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'invalid Recaptcha')), 'error')
                    return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_LOGIN_TEMPLATE)
            a=db.session.query(Admins).filter_by(username=request.form.get('username',''),password=request.form.get('password','')).all()
            # if the username and password submitted in the admin's login form matches any in the admin table the a session is initialized and the user is redirected to the admin dashbord
            if len(a)>0:
                SessionAPI.start_admin_session(session,variables={'admin_is_super_admin':a[0].super_admin,'id':a[0].id,'username':a[0].username,'email':a[0].email,'admin_avatar':a[0].admin_avatar,'phone':a[0].phone,'full_name':a[0].full_name})
                a[0].last_login_at=sqlalchemy.sql.func.now()
                db.session.commit()
                return redirect(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Incorrect username/password')), 'error')
        SessionAPI.end_admin_session(session)
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_LOGIN_TEMPLATE)


    @app.route(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH+'/',methods=['GET','POST'])
    def admin_panel_function_login_():
        if ValidatorsAPI.admin_is_authenticated(session)==True:
            return redirect(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)
        if request.method=='POST':
            if AdminDashboardSettings.ADMIN_PANEL_RECAPTCHA_ENABLED==True:
                if not GoogleReCaptchaAPI.recaptcha_app.verify():
                    SessionAPI.end_admin_session(session)
                    flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'invalid Recaptcha')), 'error')
                    return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_LOGIN_TEMPLATE)
            a=db.session.query(Admins).filter_by(username=request.form.get('username',''),password=request.form.get('password','')).all()
            # if the username and password submitted in the admin's login form matches any in the admin table the a session is initialized and the user is redirected to the admin dashbord
            if len(a)>0:
                SessionAPI.start_admin_session(session,variables={'admin_is_super_admin':a[0].super_admin,'id':a[0].id,'username':a[0].username,'email':a[0].email,'admin_avatar':a[0].admin_avatar,'phone':a[0].phone,'full_name':a[0].full_name})
                a[0].last_login_at=sqlalchemy.sql.func.now()
                db.session.commit()
                return redirect(AdminDashboardSettings.ADMIN_PANEL_BASE_URL)
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Incorrect username/password')), 'error')
        SessionAPI.end_admin_session(session)
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_LOGIN_TEMPLATE)


    # on logout we reset the session and redirect to the login page
    @app.route(AdminDashboardSettings.ADMIN_PANEL_LOGOUT_FULL_PATH)
    def admin_panel_function_logout_():
        SessionAPI.end_admin_session(session)
        return redirect(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH)

    @app.route(AdminDashboardSettings.ADMIN_PANEL_LOGOUT_FULL_PATH+'/')
    def admin_panel_function_logout():
        SessionAPI.end_admin_session(session)
        return redirect(AdminDashboardSettings.ADMIN_PANEL_LOGIN_FULL_PATH)


    @app.get(AdminDashboardSettings.ADMIN_PANEL_SET_LANGUAGE_URL+"/<language>")
    def AdminPanelSetLanguageFunction(language):
        SessionAPI.set_admin_variables(session,{AdminDashboardSettings.ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER:language})
        return redirect(request.headers.get('referer','/'))


    @app.get(AdminDashboardSettings.ADMIN_PANEL_SET_LANGUAGE_URL+"/<language>/")
    def AdminPanelSetLanguageFunction_(language):
        SessionAPI.set_admin_variables(session,{AdminDashboardSettings.ADMIN_PANEL_SET_LANGUAGE_SESSION_PARAMETER:language})
        return redirect(request.headers.get('referer','/'))


    @app.route(AdminDashboardSettings.ADMIN_PANEL_BASE_URL,methods=['GET','POST'])
    def admin_panel_function_index():
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_INDEX_TEMPLATE)


    @app.route(AdminDashboardSettings.ADMIN_PANEL_BASE_URL+'/',methods=['GET','POST'])
    def admin_panel_function_index_():
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_INDEX_TEMPLATE)


    @app.route(AdminDashboardSettings.ADMIN_PANEL_CHANGE_PASSWORD_FULL_PATH, methods=('GET', 'POST'))
    def admin_change_password():
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            return flask.abort(401)
        if request.method=='GET':
            return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_CHANGE_PASSWORD_TEMPLATE)
        if request.method=='POST' and SessionAPI.get_admin_variable(session,SessionAPI.csrf_token_name)==request.form.get(SessionAPI.csrf_token_name,''):
            a=db.session.query(Admins).filter_by(id=SessionAPI.get_admin_variable(session,'id')).all()
            if len(a)>0 and a[0].password==request.form.get('old_password',''):
                a[0].password=request.form.get('new_password','')
                db.session.commit()
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'password updated')), 'success')
            else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'incorrect old password')), 'error')
        else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'incorrect old password')), 'error')
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_CHANGE_PASSWORD_TEMPLATE)

    @app.route(AdminDashboardSettings.ADMIN_PANEL_PROFILE_FULL_PATH, methods=('GET', 'POST'))
    def admin_update_profile():
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            return flask.abort(401)
        if request.method=='GET':
            return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_PROFILE_TEMPLATE)
        if request.method=='POST' and SessionAPI.get_admin_variable(session,SessionAPI.csrf_token_name)==request.form.get(SessionAPI.csrf_token_name,''):
            a=db.session.query(Admins).filter_by(id=SessionAPI.get_admin_variable(session,'id')).all()
            if len(a)>0:
                if request.form.get('username','')!='':
                    try:
                        a[0].username=request.form.get('username','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                if request.form.get('email','')!='':
                    try:
                        a[0].email=request.form.get('email','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                if request.files['admin_avatar'].filename!='':
                    avatar_admin=FileManagerAPI.save_file(request.files['admin_avatar'],path='static/admins/admin_avatar')
                    if avatar_admin!=None and avatar_admin!='':
                        a[0].admin_avatar='/'+avatar_admin
                    flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Please upload an image')), 'error')
                if request.form.get('full_name','')!='':
                    try:
                        a[0].full_name=request.form.get('full_name','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                if request.form.get('phone','')!='':
                    try:
                        a[0].phone=request.form.get('phone','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                try:
                    db.session.commit()
                    flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'profile is updated')), 'success')
                except Exception as ex:
                    if 'admins.username' in str(ex):
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'This username is already taken')), 'error')
                    else:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'This email is already taken')), 'error')
                try:
                    SessionAPI.set_admin_variables(session,{'username':a[0].username})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'email':a[0].email})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'admin_avatar':a[0].admin_avatar})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'phone':a[0].phone})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'full_name':a[0].full_name})
                except:
                    pass
                
            else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'failed to update')), 'error')
        else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'failed to update')), 'error')
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_PROFILE_TEMPLATE)

    @app.route(AdminDashboardSettings.ADMIN_PANEL_PROFILE_FULL_PATH+'/', methods=('GET', 'POST'))
    def admin_change_password_():
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            return flask.abort(401)
        if request.method=='GET':
            return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_CHANGE_PASSWORD_TEMPLATE)
        if request.method=='POST' and SessionAPI.get_admin_variable(session,SessionAPI.csrf_token_name)==request.form.get(SessionAPI.csrf_token_name,''):
            a=db.session.query(Admins).filter_by(id=SessionAPI.get_admin_variable(session,'id')).all()
            if len(a)>0 and a[0].password==request.form.get('old_password',''):
                a[0].password=request.form.get('new_password','')
                db.session.commit()
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'password is updated')), 'success')
            else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'incorrect old password')), 'error')
        else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'incorrect old password')), 'error')
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_CHANGE_PASSWORD_TEMPLATE)

    @app.route(AdminDashboardSettings.ADMIN_PANEL_CHANGE_PASSWORD_FULL_PATH+'/', methods=('GET', 'POST'))
    def admin_update_profile_():
        if ValidatorsAPI.admin_is_authenticated(session)==False:
            return flask.abort(401)
        if request.method=='GET':
            return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_PROFILE_TEMPLATE)
        if request.method=='POST' and SessionAPI.get_admin_variable(session,SessionAPI.csrf_token_name)==request.form.get(SessionAPI.csrf_token_name,''):
            a=db.session.query(Admins).filter_by(id=SessionAPI.get_admin_variable(session,'id')).all()
            if len(a)>0:
                if request.form.get('username','')!='':
                    try:
                        a[0].username=request.form.get('username','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                if request.form.get('email','')!='':
                    try:
                        a[0].email=request.form.get('email','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                if request.files['admin_avatar'].filename!='':
                    avatar_admin=FileManagerAPI.save_file(request.files['admin_avatar'],path='static/admins/admin_avatar')
                    if avatar_admin!=None and avatar_admin!='':
                        a[0].admin_avatar='/'+avatar_admin
                    flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'Please upload an image')), 'error')
                if request.form.get('full_name','')!='':
                    try:
                        a[0].full_name=request.form.get('full_name','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                if request.form.get('phone','')!='':
                    try:
                        a[0].phone=request.form.get('phone','')
                    except Exception as ex:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,str(ex))), 'error')
                try:
                    db.session.commit()
                    flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'profile is updated')), 'success')
                except Exception as ex:
                    if 'admins.username' in str(ex):
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'This username is already taken')), 'error')
                    else:
                        flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'This email is already taken')), 'error')
                try:
                    SessionAPI.set_admin_variables(session,{'username':a[0].username})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'email':a[0].email})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'admin_avatar':a[0].admin_avatar})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'phone':a[0].phone})
                except:
                    pass
                try:
                    SessionAPI.set_admin_variables(session,{'full_name':a[0].full_name})
                except:
                    pass
                
            else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'failed to update')), 'error')
        else:
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'failed to update')), 'error')
        return AdminDashboardViewInstance.render(AdminDashboardSettings.ADMIN_APP_TEMPLATES_FOLDER+'/'+AdminDashboardSettings.ADMIN_PANEL_PROFILE_TEMPLATE)




"""
here before processing any coming requests, the app will do all necessary session and security checks. if anything goes wrong then the request won't be processed and a flash message with the error will be shown on the corresponding page
"""

@app.before_request
def check_admin_links_authorizations():
    if get_real_url_path(request.path).startswith(tuple(AdminDashboardSettings.ADMIN_PANEL_SUPER_ADMIN_LINKS)) and ValidatorsAPI.superadmin_is_authenticated(session)==False:
        return flask.abort(401)
    if get_real_url_path(request.path).startswith(tuple(AdminDashboardSettings.ADMIN_PANEL_EDITOR_ADMIN_LINKS)) and ValidatorsAPI.editor_admin_is_authenticated(session)==False:
        return flask.abort(401)
    if get_real_url_path(request.path).startswith(tuple(AdminDashboardSettings.ADMIN_PANEL_AUTHENTICATED_LINKS)) and ValidatorsAPI.admin_is_authenticated(session)==False:
        return flask.abort(401)
    if get_real_url_path(request.path).startswith(tuple(AdminDashboardSettings.ADMIN_PANEL_SUPER_ADMIN_LINKS)) and ValidatorsAPI.admin_is_authenticated(session)==True:
        return flask.abort(401)
    if get_real_url_path(request.path).startswith(tuple(ValidatorsAPI.USER_AUTHENTICATED_ENDPOINTS)) and ValidatorsAPI.user_is_authenticated(session)==False:
        return flask.redirect(ValidatorsAPI.unauthenticated_user_redirect)
    if get_real_url_path(request.path).startswith(tuple(ValidatorsAPI.USER_UNAUTHENTICATED_ENDPOINTS)) and ValidatorsAPI.user_is_authenticated(session)==True:
        return flask.redirect(ValidatorsAPI.authenticated_user_redirect)
    if get_real_url_path(request.path).startswith(tuple(ValidatorsAPI.RECAPTCHA_ENDPOINTS)) and request.method!='GET':
        if GoogleReCaptchaAPI.recaptcha_app.verify():
            GoogleReCaptchaAPI.remove_recaptcha_response(request)
        else:
                GoogleReCaptchaAPI.remove_recaptcha_response(request)
                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'invalid Recaptcha')), 'error')
                return flask.render_template(get_real_url_path(request.path)[:-1]+'.html')
    if get_real_url_path(request.path).startswith(tuple(ValidatorsAPI.CSRF_PROTECTED_USER_ENDPOINTS)) and request.method=='POST':
        if ValidatorsAPI.user_csrf_token_checker(request,session)==False:
            flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'invalid CSRF token')), 'error')
            return flask.render_template(get_real_url_path(request.path)[:-1]+'.html')
    if get_real_url_path(request.path).startswith(tuple(ValidatorsAPI.AUTO_SAVE_FILES_ENDPOINTS)):
        if request.method!='GET' and len(request.files)>0:
            d={}
            for x in request.files:
                if request.files[x].filename!='':
                    #try:
                        if ValidatorsAPI.STORAGE_TYPE=='s3':
                            d.update({x:Amazon_S3_API.save_file(request.files[x])})
                        elif ValidatorsAPI.STORAGE_TYPE=='firebase':
                            d.update({x:'/'+FirebaseAPI.upload_file(request.files[x])})
                        else:
                            saved_file=FileManagerAPI.save_file(request.files[x],path=FileManagerAPI.default_user_upload_folder,args=SessionAPI.get_user_variable(session,'id')).replace('\\','/')
                            if saved_file!=None:
                                d.update({x:'/'+saved_file})
                            else:
                                flask.flash(flask_admin.babel.gettext(TranslateInTemplate.TranslateWord_Admin(session,'invalid file type')), 'error')
                                return flask.render_template(get_real_url_path(request.path)[:-1]+'.html')
                        """except Exception as ex:
                        print(ex)"""
                else:
                    d.update({x:''})
            request.files=werkzeug.datastructures.ImmutableMultiDict(d)


#after processing the request and time to send back a response, all necessary headers will be added or removed and the request then will be logged in the logs file.

@app.after_request
def add_header(response):
    if request.method=='OPTIONS':
        HeadersAPI.set_headers(response.headers,HeadersAPI.CORS_OPTIONS_HEADERS)
    if request.path.startswith('/api/'):
        try:
            response.data= json.dumps(json.loads(response.data))
        except:
            pass
        HeadersAPI.set_headers(response.headers,HeadersAPI.CORS_HEADERS)
    HeadersAPI.set_headers(response.headers,HeadersAPI.additional_headers)
    HeadersAPI.unset_headers(response.headers,HeadersAPI.unwanted_headers)
    if '/static/' not in request.path:
        try:
            dt=time.strftime('%Y-%b-%d')
            timestamp = time.strftime('[%Y-%b-%d %H:%M:%S]')
            #create_file('logs/'+dt+'.log')
            handler = RotatingFileHandler('logs/'+dt+'.log', maxBytes=100000000, backupCount=3)
            logger = logging.getLogger('tdm')
            logger.setLevel(logging.ERROR)
            logger.addHandler(handler)
            logger.error('%s %s %s %s %s', timestamp, request.remote_addr, request.method, request.full_path, response.status)    
        except:
            pass
    return response


