// Public Esplora node endpoints. Imported ONLY by core.js's network functions and the online claim app.
// This module has NO top-level side effects, so any bundle that does not use the network (the offline key
// tool) tree-shakes it away completely, leaving zero server URLs in that bundle.
import { ACTIVE } from './config.js';

const EP = {
  testnet: { nodes: ['https://blockstream.info/testnet/api', 'https://mempool.space/testnet/api'], txExplorer: 'https://blockstream.info/testnet/tx/' },
  mainnet: { nodes: ['https://blockstream.info/api', 'https://mempool.space/api'], txExplorer: 'https://blockstream.info/tx/' },
};

export const ENDPOINTS = EP[ACTIVE] || EP.mainnet;
