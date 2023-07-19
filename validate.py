import psycopg2, datetime as dt, requests
from flask import request, request, jsonify
from .config.db.db_config_pstgr import postgresqlConfig

connpost = psycopg2.connect(postgresqlConfig)
cur = connpost.cursor()

url_auth_login = 'http://localhost:5001/aut/login'
url_auth_get_api = 'http://localhost:5001/aut/getapibyalias/'

# url_auth_login = 'http://192.168.150.156:6001/aut/login'
# url_auth_get_api = 'http://192.168.150.156:6001/aut/getapibyalias/'

token = ''
cookie = ''
momento = dt.datetime.fromtimestamp(1688410986) - dt.timedelta(days=20*365)
vencimiento_token = dt.datetime.fromtimestamp(1688410986) - dt.timedelta(days=20*365)
token_is_expired = True
session_closed = False
objetoJson = {}
api_key_pool = {}
api_key_auth = {}

def save_token_access(token='', momento='', vencimiento_token='', apikey='null'):
    try:
        apikey = api_key_pool['apikey']
    except Exception as e:
        apikey = 'null'
    query = f"""INSERT INTO token_access (token_nro, api_key_pool, hora_creacion_token, vencimiento_token)
                values( '{token}', '{apikey}', '{momento}', '{vencimiento_token}')
                ON CONFLICT (token_nro)
                DO
                UPDATE SET api_key_pool = EXCLUDED.api_key_pool;
            """
    cur.execute(query)
    connpost.commit()
    
def check_token(token):
    query = f"""SELECT 1
                FROM token_access
                where token_nro  = '{token}'
            """
    cur.execute(query)
    data = cur.fetchone()
    connpost.commit()
    return data != None

def check_vigencia_token(token, momento):
    query = f"""SELECT 1
                FROM token_access
                where token_nro  = '{token}'
                and '{momento}' between  hora_creacion_token and vencimiento_token
            """
    cur.execute(query)
    data = cur.fetchone()
    connpost.commit()
    return data == None

def get_vencimiento_token(token):
    query = f"""SELECT vencimiento_token
                FROM token_access
                where token_nro  = '{token}'
            """
    cur.execute(query)
    data = cur.fetchone()
    connpost.commit()
    return data[0]

def force_token_expiration(token):
    query = f"""update token_access set hora_creacion_token = vencimiento_token where token_nro  = '{token}' """
    cur.execute(query)
    connpost.commit()
    
def get_api_key(json_data, ambiente):
    global url_auth_get_api, api_key_pool
    objetoJson = {}
    json_data["params"]["apikey"] = api_key_auth['apikey']
    json_data["params"]["authcontext"] = ambiente
    auth_res = requests.post(url_auth_get_api + ambiente, json=json_data)
    data = auth_res.json()
    descripcion = data['descripcion']
    codigo = data['codigo']
    if codigo == 1000:
        arrayJson = data['arrayJson']
        api_key_pool = arrayJson[0]['apikey']
        objetoJson = {'apikey' : api_key_pool}
        return objetoJson
    else:
        objetoJson = None
        return objetoJson
    
    
def validator(request, token, session_closed, api_key_auth, APP_CONTEXT):
    global token_is_expired, vencimiento_token, objetoJson
    token_request = ''
    data = request.get_json()
    try:
        operation = data['operation']
        params = data['params']
        if operation == "get_token":
            momento = dt.datetime.strptime(str(dt.datetime.now()), '%Y-%m-%d %H:%M:%S.%f')
            if request.is_json:
                if request.headers.get('cookie'):
                    token_request = request.headers.get('cookie').replace('cookie=', '')
                    token_exists = check_token(token_request)
                    if token_exists:
                        token = token_request
                        token_is_expired = check_vigencia_token(token, momento)
                        if token_is_expired or session_closed:
                            res = get_login(data, api_key_auth, APP_CONTEXT, momento)
                            codigo = res['codigo']
                            descripcion = res['descripcion']
                            if codigo == 1000:
                                objetoJson = res['objetoJson']                            
                                objetoJson = {"token" : objetoJson['token']}
                                session_closed = False
                                token = objetoJson['token']
                        else:
                            vencimiento_token = get_vencimiento_token(token)                            
                            descripcion = 'Sesion ya iniciada'
                            codigo = 1100
                            respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : {}, 'arrayJson' : []}
                            return respuesta, token, momento, vencimiento_token, token_is_expired, session_closed
                    else :
                        res = get_login(data, api_key_auth, APP_CONTEXT, momento)
                        codigo = res['codigo']
                        descripcion = res['descripcion']
                        if codigo == 1000:
                            objetoJson = res['objetoJson']                    
                            objetoJson = {"token" : objetoJson['token']}
                            token = objetoJson['token']
                else :
                    res = get_login(data, api_key_auth, APP_CONTEXT, momento)
                    codigo = res['codigo']
                    descripcion = res['descripcion']
                    if codigo == 1000:
                        objetoJson = res['objetoJson']                    
                        objetoJson = {"token" : objetoJson['token']}
                        token = objetoJson['token']
                    else:
                        token = {}
                        objetoJson = {}
            else:
                descripcion = 'Json necesario para inicio de sesion'
                codigo = -1001
        else:
            descripcion = 'Operación inválida'
            codigo = -1002
    except KeyError as e :
        descripcion = 'No se encuentra el parametro: ' + str(e)
        codigo = -1001
    except Exception as e:
        descripcion = str(e)
        codigo = -1000
    respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : objetoJson, 'arrayJson' : []}
    if codigo == 1000:
        respuesta = jsonify(respuesta)
        respuesta.set_cookie('cookie', objetoJson['token'])    
    connpost.commit()
    return respuesta, token, momento, vencimiento_token, token_is_expired, session_closed


def oper_validator(request, token, api_key_auth_, vencimiento_token,  json, ambiente):
    global api_key_auth, api_key_pool
    api_key_auth = api_key_auth_
    try:
        if token:
            if request.is_json:
                if request.headers.get('cookie'):
                    token = request.headers.get('cookie').replace('cookie=', '')
                    momento = dt.datetime.strptime(str(dt.datetime.now()), '%Y-%m-%d %H:%M:%S.%f')
                    if token:
                        token_is_expired = check_vigencia_token(token, momento)
                        if token_is_expired:
                            descripcion = 'Token expirado'
                            codigo = -1010
                            respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : [], 'arrayJson': [] }
                            return respuesta
                        else:
                            if not api_key_pool:
                                api_key_pool = get_api_key(json, ambiente)
                            if api_key_pool:
                                save_token_access(token=token, apikey=api_key_pool, momento=momento, vencimiento_token=vencimiento_token)
                                descripcion = 'OK'
                                codigo = 1000
                                respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : [], 'arrayJson': [] } 
                            else:
                                descripcion = 'Api-Key no recuperada de la base de datos'
                                codigo = -1010
                                respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : [], 'arrayJson': [] } 
                else:
                    descripcion = 'Token necesario para realizar la operacion'
                    codigo = -1000
            else:
                descripcion = 'Json necesario para realizar operacion'
                codigo = -1001
        else:
            descripcion = 'Token necesario para realizar operacion'
            codigo = -1000
    except KeyError as e :
        descripcion = 'Parametro no encontrado: ' + str(e)
        codigo = -1001
    except Exception as e:
        descripcion = str(e)
        codigo = -1000
    respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : [], 'arrayJson': api_key_pool }    
    connpost.commit()
    return respuesta

def get_login(json_data, api_key_auth, APP_CONTEXT, momento):
    global vencimiento_token, session_closed
    objetoJson = {}
    arrayJson = []
    try:
        json_data["params"]["apikey"] = api_key_auth['apikey']
        json_data["params"]["authcontext"] = APP_CONTEXT
        auth_res = requests.post(url_auth_login, json = json_data)
        data = auth_res.json()
        codigo = data['codigo']
        descripcion = data['descripcion']
        if auth_res.cookies.get('cookie'):
            if codigo > 0:
                data = auth_res.json()
                token = auth_res.cookies.get('cookie')
                cookie = auth_res.cookies
                for cookies in cookie:
                    vencimiento_token = dt.datetime.fromtimestamp(cookies.expires)
                save_token_access(token=token, apikey='', momento=momento, vencimiento_token=vencimiento_token)
                session_closed = False
                objetoJson = {
                                'token' : token
                            }
    except KeyError as e :
        codigo = -1001
        descripcion = 'No se encuentra el parametro: ' + str(e)
    except Exception as e:
        codigo = -1000
        descripcion = str(e)
    respuesta =  {'codigo': codigo, 'descripcion': descripcion, 'objetoJson': objetoJson, 'arrayJson': arrayJson}
    connpost.commit()
    return respuesta

def check_my_token():
    global token_is_expired, vencimiento_token, token, session_closed
    try:
        momento = dt.datetime.strptime(str(dt.datetime.now()), '%Y-%m-%d %H:%M:%S.%f')
        if request.headers.get('cookie'):
            token_request = request.headers.get('cookie').replace('cookie=', '')
            token_exists = check_token(token_request)
            if token_exists:
                token = token_request
                token_is_expired = check_vigencia_token(token, momento)
                vencimiento_token = get_vencimiento_token(token)
                if token_is_expired:
                    codigo = -1010
                    descripcion = 'Token expirado'
                elif session_closed:
                    codigo = -1010
                    descripcion = 'La sesion ha sido cerrada'
                else:
                    codigo = 1000
                    descripcion = 'OK'
                    token_is_expired = False
                    session_closed = False
            else :
                descripcion = 'No tiene token asignado'
                codigo = -1003
        else :
            descripcion = 'No tiene token asignado'
            codigo = -1003
    except KeyError as e :
        descripcion = 'No se encuentra el parametro: ' + str(e)
        codigo = -1001
    except Exception as e:
        descripcion = str(e)
        codigo = -1000
    respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : token, 'arrayJson' : []}
    return respuesta, token, momento, vencimiento_token, token_is_expired, session_closed

def logout(token_):
    global session_closed
    if token_:
        session_closed = True
        force_token_expiration(token_)
        descripcion = 'Sesion cerrada'
        codigo = 1000
    else:
        descripcion = 'No hay sesiones para cerrar'
        codigo = 1101
    
    respuesta = {'codigo': codigo, 'descripcion': descripcion, 'objetoJson' : [], 'arrayJson' : []}
    return respuesta