// Bitcard network configuration (spec v0.4).
// Flip ACTIVE to switch the ENTIRE build between testnet and mainnet. core.js and the claim app
// read every network-specific value from here, so nothing about the network is hardcoded elsewhere.
//
// v0.4: the maker signature was removed (open-standard design — cards carry no issuer key), so
// going mainnet is now purely a network swap: set ACTIVE='mainnet'. No production key, no ceremony.
export const ACTIVE = 'mainnet';   // 'testnet' | 'mainnet'

const NETS = {
  testnet: {
    networkByte: 0x01, hrp: 'tb', label: 'TESTNET',
    nodes: ['https://blockstream.info/testnet/api', 'https://mempool.space/testnet/api'],
    txExplorer: 'https://blockstream.info/testnet/tx/',
  },
  mainnet: {
    networkByte: 0x00, hrp: 'bc', label: 'MAINNET',
    nodes: ['https://blockstream.info/api', 'https://mempool.space/api'],
    txExplorer: 'https://blockstream.info/tx/',
  },
};

export const NET = NETS[ACTIVE];
if (!NET) throw new Error('config: unknown ACTIVE network "' + ACTIVE + '"');
