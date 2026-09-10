// Pure release-metadata helpers. Kept separate so the release gate can test hash rewriting without
// contacting the live site or modifying the real README.
export function rewriteReadmeHashes(txt, want, local){
  for(const [name, hash] of Object.entries(want)){
    const src = local[name].split('/').pop();
    const pattern = new RegExp('(sha256 of app/' + src.replace('.', '\\.') + ':\\r?\\n)[0-9a-f]{64}', 'i');
    if(!pattern.test(txt)) throw new Error('could not locate the mandatory '+src+' hash field in README.md');
    txt = txt.replace(pattern, '$1'+hash);
  }
  return txt;
}
