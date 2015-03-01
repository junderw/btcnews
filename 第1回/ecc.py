# SECP256k1 curve p, n, a, b, and G values
cP = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
cN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
cA = 0
cB = 7

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
Gpt = (Gx, Gy)

def inv_mod(a, p = cP):
    lim, him = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high / low
        nm = him - lim * ratio
        new = high - low * ratio
        him = lim
        high = low
        lim = nm
        low = new
    return lim % p

def EC_add(P, Q, Pcur = cP):
    Lamda = ((Q[1] - P[1]) * inv_mod(Q[0] - P[0])) % Pcur
    x = ((Lamda ** 2) - P[0] - Q[0]) % Pcur
    y = (Lamda * (P[0] - x) - P[1]) % Pcur
    return (x, y)

def EC_double(P, Acur = cA, Pcur = cP):
    Lamda = ((3 * (P[0] ** 2) + Acur) * inv_mod(2 * P[1])) % Pcur
    x = (Lamda ** 2 - 2 * P[0]) % Pcur
    y = (Lamda * (P[0] - x) - P[1]) % Pcur
    return (x, y)

def EC_mult(Scalar, Point = Gpt):
    if Scalar == 0 or Scalar >= cN:
        raise Exception("Invalid Scalar/Private Key")
    ScalarB = str(bin(Scalar))[2:]
    Q = Point
    for i in range (1, len(ScalarB)):
        Q = EC_double(Q)
        if ScalarB[i] == "1":
            Q = EC_add(Q, Point)
    return (Q)
