import socket
import select
import random
import json
import time
from hashlib import sha3_256
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

# Threshold of Time (second) and number
class Threshold:
    def __init__(self):
        # Time (second) threshold to disconnect
        self.token_time = 30
        self.server_time = 40
        self.user_time = 10
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
auth_ip , auth_port = "0.0.0.0" , 7777
threshold = Threshold()
global_data = Data()

# Compute h(r)
def hash(r):
    return sha3_256(r).hexdigest()

# Generate challenges
def challenge_generation(m):
    n = 5
    c_list , rc_list = [] , []
    for _ in range(n):
        # Test Use
        private_key = RSA.generate(2048) 
        rc = random.getrandbits(32)
        p = json.dumps({'m': m, 'rc': rc}).encode(encoding="utf-8")
        c = PKCS1_v1_5.new(private_key.publickey()).encrypt(p)
        c_list.append(c.hex())
        rc_list.append(rc)
    return c_list, rc_list

# Disconnect socket
def socket_disconnect(sck,msg):

    inform = global_data.sockets[sck]
    if inform.get('role') == 'server':
        for token in inform['token']:
            if global_data.requests[token].get('user'):
                socket_disconnect(global_data.requests[token]['user'],msg)
            del global_data.requests[token]    
    elif inform.get('role') == 'user' and inform.get('token'):
        del global_data.requests[inform['token']]['user']

    print(f"[{global_data.sockets[sck]['addr']}] disconnect : {msg}")
    global_data.socket_list.remove(sck)
    del global_data.sockets[sck]
    sck.close()    

# Send data after check
def check_send(sck,str):
    try:
        sck.send(str)
        print(f"[{global_data.sockets[sck]['addr']}] send : {str}")
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
        if data == b'':
            socket_disconnect(sck,'Connection is closed by another side')
        else:
            warn_send(sck,'Format is invalid')
        return None

    attribute = sorted(list(data.keys()))
    if attribute == sorted(['role','token','group']):
        if data['role'] == 'server' and isinstance(data['group'],int):
            try:
                int(data['token'], 16)
                return data
            except:
                pass
    elif attribute == sorted(['role','nonce','group']):
        if data['role'] == 'user' and isinstance(data['nonce'],int) and isinstance(data['group'],int):
            return data
    elif attribute == sorted(['role','challenge']):
        if data['role'] == 'user' and isinstance(data['challenge'],int):
            return data
    warn_send(sck,'Format is invalid')
    return None

# Handle attempt failure
def attempt_failure(sck,msg):
    if not global_data.sockets[sck].get('token_attempt'):
        global_data.sockets[sck]['token_attempt'] = 0
    global_data.sockets[sck]['token_attempt'] += 1
    if global_data.sockets[sck]['token_attempt'] >= threshold.attempt_num:
        error_disconnect(sck,'Reach attempt limit')
    else:
        warn_send(sck,msg)
    return

def main():

    # Build listening socket
    auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_socket.setblocking(False)
    auth_socket.bind((auth_ip,auth_port))
    auth_socket.listen(5)
    global_data.socket_list.append(auth_socket)
    print(f"[Authenticator] : Listening on {auth_ip}:{auth_port}")

    # Receive data from socket
    while True:

        readable_sockets, _ , _ = select.select(global_data.socket_list, [], [], 0.5)

        for sck in readable_sockets:
            if sck == auth_socket:
                # Handle connect request
                object, addr = auth_socket.accept()
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
                if recv_data['role'] == 'server' and recv_data.get('token') and recv_data.get('group'):
                    if not global_data.sockets[sck].get('token'):
                        global_data.sockets[sck]['token'] = []
                    if len(global_data.sockets[sck]['token']) >= threshold.token_num:
                        warn_send(sck,'Reach token limit')
                    elif global_data.requests.get(recv_data['token']):
                        warn_send(sck,'Token is used by other servers')
                    else:
                        global_data.sockets[sck]['token'].append(recv_data['token'])
                        global_data.requests[recv_data['token']] = {'server': sck,'time': time.time(),'group': recv_data['group']}
                
                # 3. User sends r to Authenticator (checks (r, h(r)) exists or returns failed to User and Server)
                # 4. Authenticator sends c1, ..., cn  and rc1, ..., rcn to User
                elif recv_data['role'] == 'user' and recv_data.get('nonce') and recv_data.get('group'):
                    
                    token = hash(str(recv_data['nonce']).encode(encoding="utf-8"))
                    request = global_data.requests.get(token)
                    if request == None:
                        attempt_failure(sck,'Token is unmatched')
                    elif request['group'] != recv_data['group']:
                        attempt_failure(sck,'Group is unmatched')
                    elif global_data.requests[token].get('user'):
                        attempt_failure(sck,'Token is used by other users')
                    else:
                        global_data.requests[token]['user'] = sck
                        random.seed(0) # Test Use
                        m = random.getrandbits(32)
                        global_data.sockets[sck]['token'] = token
                        global_data.sockets[sck]['challenge'] = m
                        c_list, rc_list = challenge_generation(m)
                        send_data = json.dumps({'role': 'authenticator', 'ciphertexts': c_list,  'random_coins': rc_list})
                        check_send(sck,send_data.encode(encoding="utf-8"))

                # 5. User returns m to Authenticator (or stops if he/she found rc1, ..., rcn abnormal)
                # 6. Authenticator sends fin to Server
                elif recv_data['role'] == 'user' and recv_data.get('challenge'):
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
                if inform.get('user'):
                    error_disconnect(inform['user'],'Token is expired')
                del global_data.requests[token]

        # Remove socket after expiration date
        for sck in list(global_data.sockets.keys()):
            if global_data.sockets.get(sck):
                inform = global_data.sockets[sck]
                if ( inform.get('role') == 'server' and time.time() - inform['time'] > threshold.server_time ) or \
                ( inform.get('role') ==  'user'  and time.time() - inform['time'] >  threshold.user_time ) or \
                ( inform.get('role') ==   None   and time.time() - inform['time'] > threshold.socket_time ):
                    error_disconnect(sck,'Connection is expired')

if __name__ == "__main__":
    main()