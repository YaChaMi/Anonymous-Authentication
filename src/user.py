import argparse
import json
import random
from hashlib import sha3_256

import pwn
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import key_database

SERVER_PORT = 9999
SERVER_HOST = "localhost"
AUTHENTICATOR_PORT = 7777
AUTHENTICATOR_HOST = "localhost"
PRIV_KEY_DIR = "../private/"


def main():
    # parse arguments
    parser = argparse.ArgumentParser(
        description="Anonymous Authentication System - User"
    )
    parser.add_argument("--userid", "-u", type=int, required=True, help="User ID")
    parser.add_argument("--gid", "-g", type=int, required=True, help="Group ID")
    parser.add_argument("--prefix", "-p", type=int, help="Group ID prefix")
    parser.add_argument(
        "--verify", "-v", action="store_true", help="Verify if server is cheating"
    )

    args = parser.parse_args()
    userid = args.userid
    gid = args.gid
    prefix = args.prefix or 32

    key = RSA.import_key(
        open(PRIV_KEY_DIR + "/user" + str(userid) + ".pem", "rb").read()
    )

    pwn.context(log_level="debug")

    # connect to server
    sock_svr = pwn.remote(SERVER_HOST, SERVER_PORT)
    nonce = random.getrandbits(32)
    sock_svr.send(
        json.dumps(
            {
                "role": "user",
                "action": "request",
                "token": sha3_256(str(nonce).encode()).hexdigest(),
                "group": gid,
                "prefix": prefix,
            }
        ).encode()
    )

    ### begin debug only section
    # sock_fake_svr = pwn.remote(AUTHENTICATOR_HOST, AUTHENTICATOR_PORT, ssl=True)
    # sock_fake_svr.send(
    #     json.dumps(
    #         {
    #             "role": "server",
    #             "token": sha3_256(str(nonce).encode()).hexdigest(),
    #             "group": gid,
    #             "prefix": prefix,
    #         }
    #     ).encode()
    # )
    ### end debug only section

    # connect to authenticator
    sock_auth = pwn.remote(AUTHENTICATOR_HOST, AUTHENTICATOR_PORT, ssl=True)
    sock_auth.send(
        json.dumps(
            {"role": "user", "nonce": nonce, "group": gid, "prefix": prefix}
        ).encode()
    )

    # resp: {‘role’: ‘authenticator’, ‘ciphertexts’: [c1, c2, …, cn],  ‘random_coins’: [rc1, rc2, …, rcn]}
    # TODO: check if authenticator returns error message
    resp = json.loads(
        sock_auth.recvuntil(b"}]}").decode()
    )  # TODO: a better end of message
    if resp.get("msg"):
        print("Error returned by authenticator: {}".format(resp["msg"]))
        sock_svr.close()
        sock_auth.close()
        exit(1)

    # plain: "{'m': m, 'rc': rci}"
    challenges = resp["challenges"]
    answer = None
    for chal in challenges:
        if chal["userid"] == userid:
            answer = json.loads(
                PKCS1_v1_5.new(key)
                .decrypt(
                    bytes.fromhex(chal["ciphertext"]), sentinel=get_random_bytes(16)
                )
                .decode()
            )["m"]
            assert isinstance(answer, int)

            sock_auth.send(json.dumps({"role": "user", "challenge": answer}).encode())

            break
    assert answer

    if args.verify:
        # verify if authenticator is cheating
        # TODO: not correctly verified, figure it out
        pkmap = {}
        for pk in key_database.get_pubkeys(gid, prefix):
            pkmap[pk["userid"]] = RSA.import_key(pk["pubkey"])

        cheating = False
        for chal in challenges:
            pk = pkmap.get(chal["userid"])
            if not pk:
                cheating = True
                break

            expected_ciphertext = (
                PKCS1_v1_5.new(pk)
                .encrypt(json.dumps({"m": answer, "rc": chal["random_coin"]}).encode())
                .hex()
            )
            print("userid", userid)
            print("expected", expected_ciphertext)
            print("auth gives", chal["ciphertext"])
            print()
            if expected_ciphertext != chal["ciphertext"]:
                cheating = True
                break

        if cheating:
            # TODO
            print("The authenticator is cheating. Abort and report!")
            sock_svr.close()
            sock_auth.close()
            exit(1)

    # resp: {‘role’: ‘server’, ‘accept’: True/False}
    resp = sock_svr.recvuntil("}")
    resp = json.loads(resp.decode())
    if resp["accept"]:
        print("Authentication succeeded. Logging in...")
    else:
        print("Rejected by server. Failed to log in.")

    sock_svr.close()
    sock_auth.close()


if __name__ == "__main__":
    main()
