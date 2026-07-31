import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import sharp from 'sharp';

const repositoryRoot = process.cwd();
const sourceLogo = path.resolve(
  repositoryRoot,
  process.argv[2] ?? '../hush-voting-website/public/assets/hushvoting-logo.png',
);
const publicLogo = path.resolve(repositoryRoot, 'public/assets/hushvoting-logo.png');
const nextIcon = path.resolve(repositoryRoot, 'src/app/icon.png');

await mkdir(path.dirname(publicLogo), { recursive: true });
await copyFile(sourceLogo, publicLogo);
await sharp(sourceLogo).resize(512, 512).png().toFile(nextIcon);

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const result = spawnSync(npmCommand, ['exec', '--', 'tauri', 'icon', publicLogo], {
  cwd: repositoryRoot,
  stdio: 'inherit',
});

if (result.error) {
  throw result.error;
}

if (result.status !== 0) {
  throw new Error(`Tauri icon generation failed with exit code ${result.status}`);
}

console.log(`Synchronized HushVoting brand icon from ${sourceLogo}`);
