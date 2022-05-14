from Crypto.PublicKey import RSA
from Crypto.Random.random import shuffle

def generate_keypairs(n = 100):
    """ Generate public/private keys and put into public/private directory, respectively """
    for i in range(n):
        key = RSA.generate(2048)
        file_pubKey = f"../public/user{i}.pem"
        file_priKey = f"../private/user{i}.pem"
        with open(file_pubKey, 'wb') as f_pub:
            f_pub.write(key.public_key().export_key('PEM'))
        with open(file_priKey, 'wb') as f_pri:
            f_pri.write(key.export_key('PEM'))

def generate_groups(n = 100, g = 10):
    """ Divide 100 keys into 10 groups """
    numbers = list(range(n))
    shuffle(numbers)
    groups = []
    for i in range(0, 100, 10):
        groups.append(sorted(numbers[i:i+10]))
    return groups

# groups generated
# groups = [
#          [10, 27, 43, 44, 51, 66, 67, 69, 74, 88], 
#          [25, 39, 45, 53, 55, 56, 70, 75, 85, 92], 
#          [28, 29, 32, 34, 54, 59, 65, 72, 83, 84], 
#          [6, 8, 14, 15, 23, 42, 47, 80, 81, 94], 
#          [1, 3, 9, 19, 41, 50, 63, 71, 90, 99], 
#          [7, 13, 37, 38, 40, 46, 52, 61, 76, 96], 
#          [0, 18, 26, 33, 49, 57, 58, 68, 79, 93], 
#          [17, 20, 30, 35, 36, 62, 82, 87, 91, 97], 
#          [2, 11, 12, 24, 31, 48, 77, 78, 86, 95], 
#          [4, 5, 16, 21, 22, 60, 64, 73, 89, 98]
#         ]