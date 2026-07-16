#!/usr/bin/env python3
"""
Bitcard offline recovery tool  --  reconstruct your bitcoin key from a card.

WHAT THIS IS
  A Bitcard's key is split into TWO halves of 12 words each:
    Part 1 -- the words under the scratch/seal on the card
    Part 2 -- the words the buyer wrote on the card
  These are NOT a normal wallet seed. Typed into an ordinary wallet app they
  show nothing. This script combines the two halves the way Bitcard does and
  prints the funding address + the single private key that controls it, so you
  can sweep the funds with any standard Bitcoin tool -- even if Bitcard, its
  app, and its website no longer exist.

  It implements bitcard-claim-spec v0.3 using ONLY the Python standard library
  (no pip installs). Pure-Python EC math is slow but fine for a one-off recovery.

HOW TO USE
  Verify the tool works (reproduces the published test vector), then recover:

    python bitcard-recover.py --selftest
    python bitcard-recover.py --part1 "word1 ... word12" --part2 "word1 ... word12" [--mainnet]

  Output includes the P2WPKH address and the private key as WIF, which you can
  import into Electrum, Sparrow, or any wallet to move the coins.

SPEC (so anyone can re-implement this from scratch):
  half scalar  = int( HMAC-SHA512(key="Bitcoin seed",
                        PBKDF2-HMAC-SHA512(mnemonic_words, "mnemonic", 2048))[:32] ) ; reject 0 or >= n
  combined d   = (d1 + d2) mod n     (secp256k1 order n)
  address      = P2WPKH( compressed( d * G ) )   ; hrp "bc" mainnet / "tb" testnet
"""
import hashlib, hmac, sys, argparse

# ---- secp256k1 ----
Pfield = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx     = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy     = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G      = (Gx, Gy)

def _inv(a, m): return pow(a, -1, m)

def _add(p, q):
    if p is None: return q
    if q is None: return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % Pfield == 0: return None
    if p == q:
        l = (3 * x1 * x1) * _inv(2 * y1, Pfield) % Pfield
    else:
        l = (y2 - y1) * _inv(x2 - x1, Pfield) % Pfield
    x3 = (l * l - x1 - x2) % Pfield
    y3 = (l * (x1 - x3) - y1) % Pfield
    return (x3, y3)

def _mul(k, p):
    r = None
    while k:
        if k & 1: r = _add(r, p)
        p = _add(p, p); k >>= 1
    return r

# ---- BIP39 half -> scalar (words only; no wordlist needed to derive a seed) ----
def half_scalar(mnemonic):
    m = " ".join(mnemonic.lower().split())
    seed = hashlib.pbkdf2_hmac("sha512", m.encode("utf-8"), b"mnemonic", 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(I[:32], "big")
    if k == 0 or k >= N: raise ValueError("invalid half scalar (0 or >= n) -- check the words")
    return k

def compress(pt):
    x, y = pt
    return (b"\x03" if (y & 1) else b"\x02") + x.to_bytes(32, "big")

def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

# ---- bech32 (BIP173 reference implementation, public domain) ----
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25; chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk
def _hrp_expand(hrp): return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def _checksum(hrp, data):
    pm = _polymod(_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
def bech32_encode(hrp, data):
    return hrp + "1" + "".join(_CH[d] for d in data + _checksum(hrp, data))
def _convertbits(data, frm, to, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value; bits += frm
        while bits >= to:
            bits -= to; ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (to - bits)) & maxv)
    return ret
def p2wpkh(pubkey, hrp):
    return bech32_encode(hrp, [0] + _convertbits(list(hash160(pubkey)), 8, 5))

# ---- WIF (so the recovered key imports into a standard wallet) ----
def _b58(b):
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); out = ""
    while n > 0: n, r = divmod(n, 58); out = alpha[r] + out
    for byte in b:
        if byte == 0: out = "1" + out
        else: break
    return out
def to_wif(d, mainnet):
    prefix = b"\x80" if mainnet else b"\xef"
    payload = prefix + d.to_bytes(32, "big") + b"\x01"  # compressed
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58(payload + chk)

def recover(part1, part2, mainnet=False):
    d1 = half_scalar(part1); d2 = half_scalar(part2)
    d = (d1 + d2) % N
    if d == 0: raise ValueError("combined key is zero -- invalid card")
    pub = compress(_mul(d, G))
    hrp = "bc" if mainnet else "tb"
    return {"d_hex": d.to_bytes(32, "big").hex(), "pubkey": pub.hex(),
            "address": p2wpkh(pub, hrp), "wif": to_wif(d, mainnet)}

# ---- frozen test vector (bitcard-test-vectors.json) ----
_TV = {
    "part1": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "part2": "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "d":     "968eaeb422670fce07c620c22d7d41204ef45a104cb8e4a7e64e41791ad135b5",
    "pub":   "0224e2c50bd374f89dd83f7be42af1ef0a3d3092314ec76cdcbd10eea5c425a51c",
    "addr":  "tb1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrxddllm",
}
def selftest():
    r = recover(_TV["part1"], _TV["part2"], mainnet=False)
    ok = (r["d_hex"] == _TV["d"] and r["pubkey"] == _TV["pub"] and r["address"] == _TV["addr"])
    # commutativity: swapping the halves must give the same address
    swapped = recover(_TV["part2"], _TV["part1"], mainnet=False)["address"] == _TV["addr"]
    print("combined d matches vector:  ", r["d_hex"] == _TV["d"])
    print("public key matches vector:  ", r["pubkey"] == _TV["pub"])
    print("address matches vector:     ", r["address"] == _TV["addr"])
    print("halves are commutative:     ", swapped)
    print("\n" + ("SELFTEST PASS -- this tool reproduces the published vector."
                   if ok and swapped else "SELFTEST FAIL -- do not trust this copy."))
    return 0 if (ok and swapped) else 1

def main():
    ap = argparse.ArgumentParser(description="Bitcard offline recovery")
    ap.add_argument("--part1"); ap.add_argument("--part2")
    ap.add_argument("--mainnet", action="store_true", help="card marked mainnet (bc1...); default is testnet (tb1...)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest: return selftest()
    if not (a.part1 and a.part2):
        print("Usage: python bitcard-recover.py --part1 \"...12 words...\" --part2 \"...12 words...\" [--mainnet]")
        print("   or: python bitcard-recover.py --selftest")
        return 2
    r = recover(a.part1, a.part2, a.mainnet)
    print("Funding address :", r["address"])
    print("Private key WIF :", r["wif"], "  <- import into any wallet to sweep the coins")
    print("Private key hex :", r["d_hex"])
    return 0

if __name__ == "__main__":
    sys.exit(main())
