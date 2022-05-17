import ssl
import socket
import select
import random
import json
import time
from hashlib import sha3_256
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import key_database

# Threshold of Time (second) and number
class Threshold:
    def __init__(self):
        # Time (second) threshold to disconnect
        self.token_time = 150
        self.server_time = 300
        self.user_time = 60
        self.socket_time = 10
        # Token / attempt number limit per server
        self.token_num = 10
        self.attempt_num = 3

# Storage of sockets and tokens
class Data:
    def __init__(self):
        self.socket_list = []
        self.sockets = {}
        self.requests = {}

# Initialize data
auth_ip , auth_port = "0.0.0.0" , 7777 #"10.88.4.188"
threshold = Threshold()
global_data = Data()

# Compute h(r)
def hash(r):
    return sha3_256(r).hexdigest()

# Check whether key exists in dict
def dict_check(dict,key):
    return dict.get(key) != None

# Check number format and whether in the interval
def interval_check(num,low,up):
    return isinstance(num,int) and up >= num and num >= low

# Generate challenges
def challenge_generation(m,group,prefix):
    pk_list = key_database.get_pubkeys(group)
    chal_list = []
    for element in pk_list:
        uid, pk = element['userid'], RSA.import_key(element['pubkey']) 
        rc = random.getrandbits(32)
        p = json.dumps({'m': m, 'rc': rc}).encode(encoding="utf-8")
        c = PKCS1_v1_5.new(pk.publickey()).encrypt(p)
        chal_list.append({'userid': uid, 'ciphertext': c.hex(), 'random_coin': rc})
    return chal_list

# Disconnect socket
def socket_disconnect(sck,msg):

    inform = global_data.sockets[sck]
    if inform.get('role') == 'server':
        for token in inform.get('token'):
            if dict_check(global_data.requests[token],'user'):
                socket_disconnect(global_data.requests[token]['user'],msg)
            del global_data.requests[token]    
    elif inform.get('role') == 'user' and dict_check(inform,'token'):
        del global_data.requests[inform['token']]['user']

    print(f"[{global_data.sockets[sck]['addr']}] disconnect : {msg}")
    global_data.socket_list.remove(sck)
    del global_data.sockets[sck]
    sck.close()    

# Send data after check
def check_send(sck,str):
    try:
        sck.send(str)
        print(f"[{global_data.sockets[sck]['addr']}] send : {str.decode()}")
        return True
    except socket.error:
        socket_disconnect(sck,'Connection is closed by another side')
        return False

# Send a warning message
def warn_send(sck,msg):
    send_data = json.dumps({'role': 'authenticator', 'msg': msg})
    check_send(sck,send_data.encode(encoding="utf-8"))

# Disconnect socket with error
def error_disconnect(sck,msg):
    send_data = json.dumps({'role': 'authenticator', 'msg': msg})
    if check_send(sck,send_data.encode(encoding="utf-8")):
        socket_disconnect(sck,msg)

# Check data format
def format_check(sck,data):
    try:
        data = json.loads(data)
    except:
        if not data:
            socket_disconnect(sck,'Connection is closed by another side')
        else:
            warn_send(sck,'Format is invalid')
        return None

    attribute = sorted(list(data.keys()))
    if attribute == sorted(['role','token','group','prefix']):
        if data['role'] == 'server' and interval_check(data['group'],0,2**32-1) and interval_check(data['prefix'],0,32):
            try:
                int(data['token'], 16)
                return data
            except:
                pass
    elif attribute == sorted(['role','nonce','group','prefix']):
        if data['role'] == 'user' and isinstance(data['nonce'],int) and interval_check(data['group'],0,2**32-1) and interval_check(data['prefix'],0,32):
            return data
    elif attribute == sorted(['role','challenge']):
        if data['role'] == 'user' and isinstance(data['challenge'],int):
            return data
    warn_send(sck,'Format is invalid')
    return None

# Handle attempt failure
def attempt_failure(sck,msg):
    if not dict_check(global_data.sockets[sck],'token_attempt'):
        global_data.sockets[sck]['token_attempt'] = 0
    global_data.sockets[sck]['token_attempt'] += 1
    if global_data.sockets[sck]['token_attempt'] >= threshold.attempt_num:
        error_disconnect(sck,'Reach attempt limit')
    else:
        warn_send(sck,msg)
    return

def main():

    # Build listening socket
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('../certs/authenticator.crt', '../certs/authenticator.key')
    auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_socket.setblocking(False)
    auth_socket.bind((auth_ip,auth_port))
    auth_socket.listen(20)
    auth_socket = context.wrap_socket(auth_socket, server_side=True)
    global_data.socket_list.append(auth_socket)
    print(f"[Authenticator] : Listening on {auth_ip}:{auth_port}")

    # Receive data from socket
    while True:

        readable_sockets, _ , _ = select.select(global_data.socket_list, [], [], 0.5)

        for sck in readable_sockets:
            if sck == auth_socket:
                # Handle connect request
                try:
                    object, addr = auth_socket.accept()
                except:
                    continue
                print(f'Connected by {addr}')
                object.setblocking(False)
                global_data.socket_list.append(object)
                global_data.sockets[object] = {'addr': addr,'time': time.time()}
            else:
                # Check data format
                try:
                    recv_data = format_check(sck,sck.recv(1024).decode())
                except socket.error:
                    socket_disconnect(sck,'Connection is closed by another side')
                    recv_data = None
                if recv_data == None:
                    continue
                global_data.sockets[sck]['role'] = recv_data['role']
                global_data.sockets[sck]['time'] = time.time()
                print(f"[{global_data.sockets[sck]['addr']}] recv : {recv_data}")

                # 2. Server sends h(r) to Authenticator
                if recv_data['role'] == 'server' and dict_check(recv_data,'token') and dict_check(recv_data,'group') and dict_check(recv_data,'prefix'):
                    if dict_check(global_data.requests,recv_data['token']):
                        warn_send(sck,'Token is used by other servers')
                        continue
                    try:
                        key_database.get_pubkeys(recv_data['group'])
                    except:
                        warn_send(sck,'Group is inexistent')
                        continue
                    if not dict_check(global_data.sockets[sck],'token'):
                        global_data.sockets[sck]['token'] = []
                    if len(global_data.sockets[sck]['token']) >= threshold.token_num:
                        warn_send(sck,'Reach token limit')
                    else:
                        global_data.sockets[sck]['token'].append(recv_data['token'])
                        global_data.requests[recv_data['token']] = {'server': sck,'time': time.time(),'group': recv_data['group'],'prefix': recv_data['prefix']}
                
                # 3. User sends r to Authenticator (checks (r, h(r)) exists or returns failed to User and Server)
                # 4. Authenticator sends c1, ..., cn  and rc1, ..., rcn to User
                elif recv_data['role'] == 'user' and dict_check(recv_data,'nonce') and dict_check(recv_data,'group') and dict_check(recv_data,'prefix'):
                    
                    token = hash(str(recv_data['nonce']).encode(encoding="utf-8"))
                    request = global_data.requests.get(token)
                    if request == None:
                        attempt_failure(sck,'Token is unmatched')
                    elif request['group'] != recv_data['group']:
                        attempt_failure(sck,'Group is unmatched')
                    elif request['prefix'] != recv_data['prefix']:
                        attempt_failure(sck,'Prefix is unmatched')
                    elif dict_check(global_data.requests[token],'user'):
                        attempt_failure(sck,'Token is used by other users')
                    elif dict_check(global_data.sockets[sck],'token'):
                        attempt_failure(sck,'You have used a token')
                    else:
                        global_data.requests[token]['user'] = sck
                        m = random.getrandbits(32)
                        global_data.sockets[sck]['token'] = token
                        global_data.sockets[sck]['challenge'] = m
                        chal_list = challenge_generation(m,request['group'],request['prefix'])
                        send_data = json.dumps({'role': 'authenticator', 'challenges': chal_list})
                        check_send(sck,send_data.encode(encoding="utf-8"))

                # 5. User returns m to Authenticator (or stops if he/she found rc1, ..., rcn abnormal)
                # 6. Authenticator sends fin to Server
                elif recv_data['role'] == 'user' and dict_check(recv_data,'challenge'):
                    fin = True if recv_data['challenge'] == global_data.sockets[sck]['challenge'] else False                    
                    token = global_data.sockets[sck]['token']
                    server = global_data.requests[token]['server']
                    send_data = json.dumps({'role': 'authenticator', 'token': token,  'accept': fin})
                    check_send(server,send_data.encode(encoding="utf-8"))
                    socket_disconnect(sck,'End of anonymous authentication')
                    if fin == True:
                        global_data.sockets[server]['token'].remove(token)
                        del global_data.requests[token]

        # Remove token after expiration date
        for token in list(global_data.requests.keys()):
            inform = global_data.requests[token]
            if time.time() - inform['time'] > threshold.token_time:
                server = inform['server']
                send_data = json.dumps({'role': 'authenticator', 'token': token,  'accept': False})
                global_data.sockets[server]['token'].remove(token)
                check_send(server,send_data.encode(encoding="utf-8"))         
                if dict_check(inform,'user'):
                    error_disconnect(inform['user'],'Token is expired')
                del global_data.requests[token]

        # Remove socket after expiration date
        for sck in list(global_data.sockets.keys()):
            if dict_check(global_data.sockets,sck):
                inform = global_data.sockets[sck]
                if ( inform.get('role') == 'server' and time.time() - inform['time'] > threshold.server_time ) or \
                   ( inform.get('role') ==  'user'  and time.time() - inform['time'] >  threshold.user_time  ) or \
                   ( inform.get('role') ==   None   and time.time() - inform['time'] > threshold.socket_time ):
                    error_disconnect(sck,'Connection is expired')

if __name__ == "__main__":
    main() 