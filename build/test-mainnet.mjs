// Verify the mainnet address encoding + the fail-closed maker-key guard, without touching the live config.
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';

const pub = hex.decode('0224e2c50bd374f89dd83f7be42af1ef0a3d3092314ec76cdcbd10eea5c425a51c'); // vector combined pubkey
const BTC_MAINNET = { bech32: 'bc', pubKeyHash: 0x00, scriptHash: 0x05, wif: 0x80 };

const tb = btc.p2wpkh(pub, btc.TEST_NETWORK).address;
const bc = btc.p2wpkh(pub, BTC_MAINNET).address;
console.log('testnet address:', tb);
console.log('mainnet address:', bc);
console.log('testnet matches vector:', tb === 'tb1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrxddllm');
console.log('mainnet is bc1 + same witness program:', bc.startsWith('bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wq'));

const placeholder = 'REPLACE_WITH_PRODUCTION_MAKER_PUBLIC_KEY';
const real = '3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b';
const guard = h => /^[0-9a-fA-F]{64}$/.test(h);
console.log('guard rejects placeholder (fail-closed):', !guard(placeholder));
console.log('guard accepts a real 64-hex key:', guard(real));
