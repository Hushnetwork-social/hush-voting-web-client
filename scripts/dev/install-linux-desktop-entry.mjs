import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

if (process.platform !== 'linux') {
  console.log('Skipping Linux desktop identity installation on this platform.');
  process.exit(0);
}

const repositoryRoot = process.cwd();
const applicationsDirectory = path.join(os.homedir(), '.local/share/applications');
const iconsDirectory = path.join(os.homedir(), '.local/share/icons/hicolor/512x512/apps');
const desktopEntry = path.join(applicationsDirectory, 'hush-voting-app.desktop');
const installedIcon = path.join(iconsDirectory, 'hush-voting-app.png');
const sourceIcon = path.join(repositoryRoot, 'src-tauri/icons/icon.png');
const launcher = path.join(repositoryRoot, 'scripts/dev/open-ubuntu-app.sh');

await mkdir(applicationsDirectory, { recursive: true });
await mkdir(iconsDirectory, { recursive: true });
await copyFile(sourceIcon, installedIcon);
await writeFile(
  desktopEntry,
  `[Desktop Entry]\nName=HushVoting!\nComment=Private, governed election workflows\nExec=${launcher}\nIcon=hush-voting-app\nStartupWMClass=hush-voting-app\nTerminal=false\nType=Application\nCategories=Office;Utility;\n`,
  'utf8',
);

for (const [command, args] of [
  ['update-desktop-database', [applicationsDirectory]],
  ['gtk-update-icon-cache', ['--force', '--ignore-theme-index', path.join(os.homedir(), '.local/share/icons/hicolor')]],
]) {
  const result = spawnSync(command, args, { stdio: 'ignore' });
  if (result.error && result.error.code !== 'ENOENT') {
    throw result.error;
  }
}

console.log(`Installed HushVoting development desktop identity: ${desktopEntry}`);
