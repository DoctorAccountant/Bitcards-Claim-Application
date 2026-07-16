// Bitcard network configuration (spec v0.4).
// Flip ACTIVE to switch the ENTIRE build between testnet and mainnet. core.js and the claim app
// read every network-specific value from here, so nothing about the network is hardcoded elsewhere.
//
// v0.4: the maker signature was removed (open-standard design — cards carry no issuer key), so
// going mainnet is now purely a network swap: set ACTIVE='mainnet'. No production key, no ceremony.
export const ACTIVE = 'mainnet';   // 'testnet' | 'mainnet'

// Crypto/display params only (NO server URLs). The node endpoints live in the separate, side-effect-free
// endpoints.js so the OFFLINE tool (which calls no network functions) tree-shakes every node URL out of its bundle.
const NETS = {
  testnet: { networkByte: 0x01, hrp: 'tb', label: 'TESTNET' },
  mainnet: { networkByte: 0x00, hrp: 'bc', label: 'MAINNET' },
};

export const NET = NETS[ACTIVE];
if (!NET) throw new Error('config: unknown ACTIVE network "' + ACTIVE + '"');
