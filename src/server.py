from multiprocessing import context
import select
import socket
import key_database
import json
import ssl
import pwn

def check_group_prefix(group,prefix):
    return True
def format_check(pack,p_from):      #p_from:1->auth,2->user
    if p_from==1 and pack.get('token') and pack.get('token'):
        return True
    elif p_from==2 and pack.get('role') and pack.get('token') and pack.get('group') and pack.get('prefix') and pack.get('action'):
        return True
    return False
def start_Authenticator(host, port):
    # Build listening socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # require a certificate from the server
    s = ssl.wrap_socket(s,
                    keyfile="../certs/server-client.key",
                    certfile="../certs/server-client.crt",
                    ca_certs="../certs/ca.crt",
                    cert_reqs=ssl.CERT_REQUIRED)
    # s.bind((host,9299))
    s.connect((host,port))
    s.setblocking(False)
    # data=s.recv() 
    # print(data.decode())   


    return s
def reconnect_Auth(inputs,outputs,A_HOST,A_PORT,authenticator):
    print('reconnect auth')
    inputs.remove(authenticator)
    outputs.remove(authenticator)
    authenticator=start_Authenticator(A_HOST,A_PORT)
    inputs.insert(1,authenticator)
    outputs.insert(1,authenticator)
    return inputs,outputs,authenticator

def start_server(host,port,a_host,a_port):
    #SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('../certs/server.crt', '../certs/server.key')
    #server
    HOST = host
    PORT = port
    #Authenticator
    A_HOST=a_host
    A_PORT=a_port
    #server_bulid
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))  
    server.setblocking(False)
    server.listen(10)  
    server = context.wrap_socket(server, server_side=True)
    #call Authenticator
    authenticator=start_Authenticator(A_HOST,A_PORT)
    authenticator_w=[]#something wait for send to auth
    #input:readable_set, output:writable_set, token_user_dict:token->user, arr_w:user->something_for_output
    inputs = [server,authenticator]
    outputs = [authenticator]                
    token_user_dict={}      
    arr_w={}    
    #user->token dict
    user_token_dict={}

    while inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        for s in readable:
            if s is server:     #there is a user
                connection, client_address = s.accept()
                inputs.append(connection)
                outputs.append(connection)
            elif s is authenticator:     #authenticator
                try:
                    data = s.recv(1024)
                except ssl.SSLWantReadError:
                    continue
                if not data:
                    #disconnect, reset authenticator
                    authenticator.close()
                    inputs,outputs,authenticator=reconnect_Auth(inputs,outputs,A_HOST,A_PORT,authenticator)
                else:
                    print(f"{s.getpeername()} recv auth: {data}")
                    pack=json.loads(data.decode())
                    if(format_check(pack,1)):
                    #read something from auth
                        tmp_token=pack['token']
                        if(pack['role']!='authenticator'):          #connect to wrong party
                            inputs,outputs,authenticator=reconnect_Auth(inputs,outputs,A_HOST,A_PORT,authenticator)
                        elif(tmp_token in token_user_dict):         #normally get fin or get authenticator's warn
                            pack['role']='server'
                            tmp_user=token_user_dict[tmp_token]
                            del pack['token']
                            user_pack=json.dumps(pack)
                            arr_w[tmp_user]=user_pack.encode()
                    else:
                        authenticator.close()
                        inputs,outputs,authenticator=reconnect_Auth(inputs,outputs,A_HOST,A_PORT,authenticator)
            else:
                data = s.recv(1024)
                if data:
                    print(f"{s.getpeername()} recv user: {data}")
                    #read user's data
                    pack=json.loads(data.decode())
                    if(format_check(pack,2)):
                        if(pack['action']=='request' and check_group_prefix(pack['group'],pack['prefix'])):
                            token_user_dict[pack['token']]=s
                            user_token_dict[s]=pack['token']
                            pack['role']='server'
                            del pack['action']
                            msg=json.dumps(pack)
                            authenticator_w.append(msg.encode())
                            if s not in outputs:
                                outputs.append(s)
                        else:
                            #wrong action/group/prefix
                            reject={'role':'server','accept':'False','msg':'Wrong action/group/prefix'}
                            rej=json.dumps(reject)
                            arr_w[s]=rej.encode()
                    else:
                        #wrong format
                        reject={'role':'server','accept':'False','msg':'Wrong format'}
                        rej=json.dumps(reject)
                        arr_w[s]=rej.encode()
                else:
                    print(f'disconnect, remove user {user_token_dict[s]}')
                    #disconnect,remove user
                    if s in user_token_dict:
                        if user_token_dict[s] in token_user_dict:
                            del token_user_dict[user_token_dict[s]]
                        del user_token_dict[s]
                    if s in outputs:
                        outputs.remove(s)
                    inputs.remove(s)
                    s.close()
        for w in writable:
            if w is authenticator:
                for aw in authenticator_w:
                    print(f'{authenticator.getpeername()} send auth: {aw}')
                    authenticator.send(aw)
                    authenticator_w.remove(aw)
            else:
                if w in arr_w:
                    print(f'{w.getpeername()} send user: {arr_w[w]}')
                    w.send(arr_w[w])
                    del arr_w[w]
                    if w in user_token_dict:
                        if user_token_dict[w] in token_user_dict:
                            del token_user_dict[user_token_dict[w]]
                        del user_token_dict[w]
                    if w in outputs:
                        outputs.remove(w)
                    inputs.remove(w)
                    w.close()

def main():
    host="localhost"
    port=9999
    a_host="localhost"
    a_port=7777
    start_server(host,port,a_host,a_port)
    
                
if __name__ == "__main__":
    main()