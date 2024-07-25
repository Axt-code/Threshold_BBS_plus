from py_ecc.bls12_381 import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random

def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 4) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX(x)
        if beta == pow(y, 2, field_modulus):
            return(FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def to_binary256(point) :
    if isinstance(point, str):
        return sha256(point.encode("utf8").strip()).digest()
    if isinstance(point, int):
        return point.to_bytes(32, 'big')
    if isinstance(point[0], FQ):
        point1 = point[0].n.to_bytes(32, 'big')
        point2 = point[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()
    if isinstance(point[0], FQ2):
        point1 = point[0].coeffs[0].n.to_bytes(32, 'big') + point[0].coeffs[1].n.to_bytes(32, 'big')
        point2 = point[1].coeffs[0].n.to_bytes(32, 'big') + point[1].coeffs[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()

def setup(q=1, AC = "h"):
    assert q > 0
    hs = [hashG1((AC+"%s"%i).encode("utf8")) for i in range(q)]
    return ((FQ, FQ2, FQ12), curve_order, G1, hs, G2, pairing)

def poly_eval(coeff, x):
    """ evaluate a polynomial defined by the list of coefficient coeff at point x """
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ttp_keygen(params, t, n):
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    assert n >= t and t > 0 and q > 0
    # generate polynomials
    v = [random.randint(2, o) for _ in range(0,t)]
    w = [[random.randint(2, o) for _ in range(0,t)] for _ in range(q)]
    # generate shares
    x = [poly_eval(v,i) % o for i in range(1,n+1)]
    y = [[poly_eval(wj,i) % o for wj in w] for i in range(1,n+1)]
    # set keys
    sk = list(zip(x, y))
    vk = [(g2, multiply(g2, x[i]), [multiply(g1, y[i][j]) for j in range(len(y[i]))], [multiply(g2, y[i][j]) for j in range(len(y[i]))]) for i in range(len(sk))]
    return (sk, vk)

def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret
    
def modInverse(a, m):
    m0 = m
    y = 0
    x = 1 
    if (m == 1):
        return 0
    while (a > 1):
        # q is quotient
        q = a // m
        t = m
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0):
        x = x + m0
    return x

def lagrange_basis(indexes, o, x=0):
    """ generates all lagrange basis polynomials """
    l = []
    for i in indexes:
        numerator, denominator = 1, 1
        for j in indexes:
            if j != i:
                numerator = (numerator * (x - j)) % o
                denominator = (denominator * (i - j)) % o
        l.append((numerator * modInverse(denominator, o)) % o)
    return l

def agg_key(params, vks):
    (G, o, g1, hs, g2, e) = params
    # filter missing keys (in the threshold setting)
    filter = [vks[i] for i in range(len(vks)) if vks[i] is not None]
    indexes = [i+1 for i in range(len(vks)) if vks[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate keys
    (_, alpha, g1_beta, beta) = zip(*filter)
    q = len(beta[0])
    aggr_alpha = ec_sum([multiply(alpha[i], l[i]) for i in range(len(filter))])
    aggr_g1_beta = [ec_sum([multiply(g1_beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_beta = [ec_sum([multiply(beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_vk = (g2, aggr_alpha, aggr_g1_beta, aggr_beta)
    return aggr_vk