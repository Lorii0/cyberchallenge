import itertools
def scramble(message, key):
    W = len(key)
    while len(message) % (2*W):
        message += "#"

    for _ in range(128):
        message = message[1:] + message[:1]
        message = message[0::2] + message[1::2]
        message = message[1:] + message[:1]
        res = ""
        for j in range(0, len(message), W):
            for k in range(W):
                res += message[j:j+W][key[k]]
        message = res

    return message


def unscramble(message, key):
    W=len(key)

    for _ in range(128):
        res = ""
        for j in range(0 , len(message), W):
            tmp = ['']* W
            b = message[j:j+W]
            for k in range(W):
                tmp[key[k]]=b[k]

            res += "".join(tmp)
        message = res

        message = message[-1:] + message[:-1]
        mid = len(message) // 2
        tmp = ""
        for i in range(mid):
            tmp += message[i]+message[i+mid]
        
        message = tmp

        message = message[-1:] + message[:-1]
    return message
        

        

    

flag = "CCIT{write_flag_here_before_the_ctf_nigga}"
key = list(range(7))
scrambled = "l_4Tnb_3cnnbcg3r3slCCm4Id__gb4u}ct{0mr3sds"

for maybe in itertools.permutations(key):
    unscrambled = unscramble(scrambled,list(maybe))
    if "CCIT{" in unscrambled:
        print(unscrambled)
