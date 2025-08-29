const fs = require('fs');
const path = require('path');

const clientDirs = ['client/dist', 'client/build', 'client/out']; // 프론트 빌드 폴더 후보
const projectRoot = __dirname + '/../';
const publicDir = path.resolve(projectRoot, 'public');

function findClientBuild() {
  for (const d of clientDirs) {
    const p = path.resolve(projectRoot, d);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function copyRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });

  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const e of entries) {
    const srcPath = path.join(src, e.name);
    const destPath = path.join(dest, e.name);
    if (e.isDirectory()) {
      copyRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

const clientBuild = findClientBuild();
if (!clientBuild) {
  console.log('No client build found. Expected one of:', clientDirs.join(', '));
  process.exit(0); // 실패로 중단시키지 않음
}

console.log('Copying client build from', clientBuild, 'to', publicDir);
copyRecursive(clientBuild, publicDir);
console.log('Done.');
