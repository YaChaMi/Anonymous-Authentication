from Crypto.PublicKey import RSA
import json

# database should record userid, gid, pubKey
# group should be disjoint
# send from authenticator: 
# {'role': 'authenticator', 'action': 'get_pubkeys', 'group': gid}
# group id: gid

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

def get_pubkeys(gid):
    """
    Given a group id, return public keys in this group in the form:
    [{'userid': uid, 'pubkey': pubKey_uid}, {'userid': uid, 'pubkey': pubKey_uid},...]
    where pubKey_uid is a utf-8 string decoded from bytes
    """
    pub_keys = []
    for uid in groups[gid]:
        file_pubKey = f"../public/user{uid}.pem"
        with open(file_pubKey, 'r') as f_pub:
            pubKey = RSA.import_key(f_pub.read())
        pub_key = {'userid': uid, 'pubkey': pubKey.public_key().export_key('PEM').decode('utf-8')}
        pub_keys.append(pub_key)
    return pub_keys

def req_pubkeys(pkt):
    """
    The authenticator request all public keys from database in the form:
    {'role': 'authenticator', 'action': 'get_pubkeys', 'group': gid}
    return selected public keys with gid in the form:
    {'role': 'database', 'pubkeys': pubkeys}
    """
    req = json.loads(pkt)
    assert req['role'] == 'authenticator'
    assert req['action'] == 'get_pubkeys'
    gid = req['group']
    # prefix = pkt['prefix'] # not yet implemented for now
    return json.dumps({'role': 'database', 'pubkeys': get_pubkeys(gid)})

# # Testing the API
# pkt = json.dumps({'role': 'authenticator', 'action': 'get_pubkeys', 'group': 9})
# res = req_pubkeys(pkt)
# data = json.loads(res)
# print(data['role'])
# print(data['pubkeys'])
# print()
# for pub_key in data['pubkeys']:
#     print(pub_key['userid'])
#     print(pub_key['pubkey'].encode()) # get the original bytes encoded pubkey