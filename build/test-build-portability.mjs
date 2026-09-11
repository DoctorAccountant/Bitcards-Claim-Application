// Reproduce every released HTML file while running from an unrelated directory. This catches build
// inputs that accidentally point at a developer's home folder or depend on the current directory.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = new URL('./', import.meta.url);
const assemblerUrl = new URL('assemble.mjs', here);
const assembler = fileURLToPath(assemblerUrl);
const source = readFileSync(assemblerUrl, 'utf8');

const fail = message => {
  console.error('FAIL build portability: ' + message);
  process.exit(1);
};

// A drive-qualified path, a Unix home path or the former OneDrive dependency must never return.
// Require a path-like boundary before the drive letter so text such as "https://" is not mistaken
// for the `s:/` drive path.
if (/(?:^|[='"\s(])[A-Za-z]:[\\/]/m.test(source) || /\/(?:Users|home)\//.test(source) || /OneDrive/i.test(source)) {
  fail('assemble.mjs contains a machine-specific absolute path');
}

const fonts = [
  'k3kPo8UDI-1M0wlSV9XAw6lQkqWY8Q82sLydOxI.woff2',
  'NGSwv5HMAFg6IuGlBNMjxLsH8ag.woff2',
  '-F63fjptAgt5VM-kVkqdyU8n1i8q1w.woff2'
];
for (const font of fonts) {
  if (!existsSync(new URL('assets/fonts/' + font, here))) fail('missing vendored font: ' + font);
}
if (!existsSync(new URL('assets/fonts/OFL-1.1.txt', here))) fail('missing font licence');

const temp = mkdtempSync(join(tmpdir(), 'bitcard-portable-build-'));
try {
  for (const target of [
    ['template-claim.html', 'app-claim.bundle.js', '../app/claim-app.html', 'claim-app.html'],
    ['template-offline.html', 'app-offline.bundle.js', '../app/offline.html', 'offline.html'],
    ['template-qc.html', 'app-qc.bundle.js', '../print/qc-tool.html', 'qc-tool.html']
  ]) {
    const [template, bundle, released, outputName] = target;
    const output = join(temp, outputName);
    execFileSync(process.execPath, [
      assembler,
      fileURLToPath(new URL(template, here)),
      fileURLToPath(new URL(bundle, here)),
      output
    ], { cwd: temp, stdio: 'pipe' });

    const built = readFileSync(output);
    const expected = readFileSync(new URL(released, here));
    if (!built.equals(expected)) fail(outputName + ' does not reproduce the released artifact byte for byte');
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('PASS portable clean build: repository inputs only; all released artifacts reproduced byte for byte');
