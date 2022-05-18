from Crypto.PublicKey import RSA
import json

# database should record userid, gid, pubKey
# groups should be disjoint
# json received from authenticator: 
# {'role': 'authenticator', 'action': 'get_pubkeys', 'group': gid, 'prefix': prefix}

groups = [
         [10, 27, 43, 44, 51, 66, 67, 69, 74, 88], 
         [25, 39, 45, 53, 55, 56, 70, 75, 85, 92], 
         [28, 29, 32, 34, 54, 59, 65, 72, 83, 84], 
         [6, 8, 14, 15, 23, 42, 47, 80, 81, 94], 
         [1, 3, 9, 19, 41, 50, 63, 71, 90, 99], 
         [7, 13, 37, 38, 40, 46, 52, 61, 76, 96], 
         [0, 18, 26, 33, 49, 57, 58, 68, 79, 93], 
         [17, 20, 30, 35, 36, 62, 82, 87, 91, 97], 
         [2, 11, 12, 24, 31, 48, 77, 78, 86, 95], 
         [4, 5, 16, 21, 22, 60, 64, 73, 89, 98]
        ]

def get_pubkeys(gid, prefix = 32):
    """
    Given a gid and a prefix, return public keys of these groups in the form:
    [{'userid': uid, 'pubkey': pubKey_uid}, {'userid': uid, 'pubkey': pubKey_uid},...]
    where pubKey_uid is a utf-8 string decoded from bytes
    """
    uid_list = []
    # Suppose prefix only within 0 ~ 32
    if 0 <= prefix and prefix <= 31:
        mask = 2 ** (32 - prefix)
        mod = gid % mask
        start = gid - mod # Suppose gid <= 9
        stop = min(start+mask, len(groups))
        for i in range(start, stop):
            uid_list += groups[i]
        uid_list.sort()
    else:
        uid_list += groups[gid]
        
    pub_keys = []
    for uid in uid_list:
        file_pubKey = f"../public/user{uid}.pem"
        with open(file_pubKey, 'r') as f_pub:
            pubKey = RSA.import_key(f_pub.read())
        pub_key = {'userid': uid, 'pubkey': pubKey.public_key().export_key('PEM').decode('utf-8')}
        pub_keys.append(pub_key)
    return pub_keys

def req_pubkeys(pkt):
    """
    The authenticator request all public keys from database in the form:
    {'role': 'authenticator', 'action': 'get_pubkeys', 'group': gid, 'prefix': prefix}
    return selected public keys with gid in the form:
    {'role': 'database', 'pubkeys': pubkeys}
    """
    req = json.loads(pkt)
    assert req['role'] == 'authenticator'
    assert req['action'] == 'get_pubkeys'
    gid = req['group']
    prefix = req['prefix']
    return json.dumps({'role': 'database', 'pubkeys': get_pubkeys(gid, prefix)})

# # Testing the API
# pkt = json.dumps({'role': 'authenticator', 'action': 'get_pubkeys', 'group': 8, 'prefix': 29})
# res = req_pubkeys(pkt)
# data = json.loads(res)
# print(data['role'])
# print(data['pubkeys'])
# print()
# for pub_key in data['pubkeys']:
#     print(pub_key['userid'])
#     print(pub_key['pubkey'].encode()) # get the original bytes encoded pubkey
# print()
# print(len(data['pubkeys']))