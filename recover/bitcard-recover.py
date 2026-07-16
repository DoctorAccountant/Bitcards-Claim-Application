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

  It implements bitcard-claim-spec v0.4 using ONLY the Python standard library
  (no pip installs). Pure-Python EC math is slow but fine for a one-off recovery.

HOW TO USE
  Verify the tool works (reproduces the published test vectors), then recover.
  The mainnet release makes bc1... cards, so mainnet is the DEFAULT.

    python bitcard-recover.py --selftest
    python bitcard-recover.py                       (then paste each half when prompted)
    python bitcard-recover.py --part1 "...12 words..." --part2 "...12 words..." [--testnet]

  For safety the tool VALIDATES both halves (12 real BIP39 words + checksum) and
  refuses to derive a key from a mistyped word, so a typo becomes a clear error
  instead of a silently wrong address. Prefer the interactive prompt: words typed
  as command-line arguments can linger in your shell history and process list.

  Output includes the P2WPKH address and the private key as WIF. Use your wallet's
  SWEEP feature (Electrum/Sparrow: "Sweep"), not "import", so the coins move to a
  fresh key you control. A Bitcard key is a one-time bearer key; do not keep or reuse it.

SPEC (so anyone can re-implement this from scratch):
  half scalar  = int( HMAC-SHA512(key="Bitcoin seed",
                        PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic", 2048))[:32] ) ; reject 0 or >= n
  combined d   = (d1 + d2) mod n     (secp256k1 order n)
  address      = P2WPKH( compressed( d * G ) )   ; hrp "bc" mainnet / "tb" testnet
"""
import hashlib, hmac, sys, argparse, unicodedata, getpass

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

# ---- BIP39 English wordlist (embedded so this tool needs no external files) ----
_WORDS = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo".split()
_WORD_INDEX = {w: i for i, w in enumerate(_WORDS)}

def _normalize(mnemonic):
    # BIP39: NFKD; collapse whitespace; English list is lowercase ASCII
    return unicodedata.normalize("NFKD", " ".join(str(mnemonic).split())).lower()

def validate_mnemonic(mnemonic):
    """Reject anything that is not a valid BIP39 mnemonic (word count, membership, checksum).
    Returns the normalized mnemonic, or raises ValueError with an actionable message."""
    m = _normalize(mnemonic)
    words = m.split()
    if len(words) != 12:
        raise ValueError("expected 12 words but got %d -- check the card" % len(words))
    if len(_WORDS) != 2048:
        raise ValueError("embedded wordlist is corrupt (%d words, expected 2048) -- do not trust this copy" % len(_WORDS))
    idx = []
    for i, w in enumerate(words):
        if w not in _WORD_INDEX:
            raise ValueError("word %d ('%s') is not on the BIP39 word list -- likely a typo" % (i + 1, w))
        idx.append(_WORD_INDEX[w])
    bits = "".join(format(v, "011b") for v in idx)          # 12 * 11 = 132 bits
    ent_len = len(bits) * 32 // 33                            # 128 entropy bits
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    want = format(hashlib.sha256(ent).digest()[0], "08b")[: len(bits) - ent_len]
    if bits[ent_len:] != want:
        raise ValueError("these 12 words do not pass their built-in checksum -- a word is mistyped or out of order")
    return m

# ---- BIP39 half -> scalar ----
def half_scalar(mnemonic):
    m = validate_mnemonic(mnemonic)          # LOUD failure on any typo, before we derive anything
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

def recover(part1, part2, mainnet=True):
    d1 = half_scalar(part1); d2 = half_scalar(part2)
    d = (d1 + d2) % N
    if d == 0: raise ValueError("combined key is zero -- invalid card")
    pub = compress(_mul(d, G))
    hrp = "bc" if mainnet else "tb"
    return {"d_hex": d.to_bytes(32, "big").hex(), "pubkey": pub.hex(),
            "address": p2wpkh(pub, hrp), "wif": to_wif(d, mainnet)}

# ---- frozen test vectors (bitcard-test-vectors.json); mainnet is the same key on hrp "bc" ----
_TV = {
    "part1": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "part2": "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "d":     "968eaeb422670fce07c620c22d7d41204ef45a104cb8e4a7e64e41791ad135b5",
    "pub":   "0224e2c50bd374f89dd83f7be42af1ef0a3d3092314ec76cdcbd10eea5c425a51c",
    "addr_testnet": "tb1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrxddllm",
    "addr_mainnet": "bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg",
}
def selftest():
    t = recover(_TV["part1"], _TV["part2"], mainnet=False)
    m = recover(_TV["part1"], _TV["part2"], mainnet=True)
    swapped = recover(_TV["part2"], _TV["part1"], mainnet=True)["address"] == _TV["addr_mainnet"]
    # a deliberately mistyped word MUST be rejected, not silently turned into a wrong key
    rejected = False
    try: recover("abandno abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", _TV["part2"])
    except ValueError: rejected = True
    checks = {
        "combined d matches vector":        t["d_hex"] == _TV["d"],
        "public key matches vector":        t["pubkey"] == _TV["pub"],
        "testnet address matches vector":   t["address"] == _TV["addr_testnet"],
        "mainnet address matches vector":   m["address"] == _TV["addr_mainnet"],
        "halves are commutative":           swapped,
        "wordlist has 2048 words":          len(_WORDS) == 2048,
        "mistyped word is rejected":        rejected,
    }
    for k, v in checks.items(): print("  %-34s %s" % (k + ":", v))
    ok = all(checks.values())
    print("\n" + ("SELFTEST PASS -- this tool reproduces the published vectors."
                  if ok else "SELFTEST FAIL -- do not trust this copy."))
    return 0 if ok else 1

def _get_half(label, supplied):
    if supplied:
        return supplied
    print("Type the 12 %s words (they will not be echoed), then press Enter." % label)
    return getpass.getpass("  %s: " % label)

def main():
    ap = argparse.ArgumentParser(description="Bitcard offline recovery (spec v0.4)")
    ap.add_argument("--part1"); ap.add_argument("--part2")
    ap.add_argument("--testnet", action="store_true", help="card marked testnet (tb1...); default is mainnet (bc1...)")
    ap.add_argument("--mainnet", action="store_true", help="explicit mainnet (this is already the default)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest: return selftest()
    if a.testnet and a.mainnet:
        print("Choose one network, not both --testnet and --mainnet."); return 2
    mainnet = not a.testnet
    if a.part1 or a.part2:
        print("Note: words passed on the command line can be saved in shell history. The prompt is safer.\n")
    try:
        part1 = _get_half("Part 1 (under the seal)", a.part1)
        part2 = _get_half("Part 2 (handwritten)", a.part2)
        if not (part1 and part2):
            print("Both halves are required."); return 2
        r = recover(part1, part2, mainnet)
    except ValueError as e:
        print("Could not recover: %s" % e); return 1
    print("\nNetwork          :", "mainnet (bc1...)" if mainnet else "testnet (tb1...)")
    print("Funding address :", r["address"])
    print("Private key WIF :", r["wif"], "  <- SWEEP this with a wallet (Electrum/Sparrow 'Sweep'); do not 'import' and reuse it")
    print("Private key hex :", r["d_hex"])
    return 0

if __name__ == "__main__":
    sys.exit(main())
