#!/usr/bin/env node
/** FEAT-009 AC-009-073, Phase 6 Tasks 6.9/6.10: execute both real FEAT-001 runtimes. */
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const server = resolve(repo, '../hush-server-node');
const corpus = join(repo, 'conformance/identity/v1');
const output = join(repo, 'conformance/reports/credential-file-restore');
const summaryPath = join(output, 'summary.json');
const project = join(server, 'Tools/HushIdentityCompatibilityConformance/HushIdentityCompatibilityConformance.csproj');
const assembly = join(dirname(project), 'bin/Debug/net10.0/HushIdentityCompatibilityConformance.dll');
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
let child;
let interrupted = false;
let built = false;
function killOwned() {
  if (child?.pid) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
}
function interrupt() { interrupted = true; killOwned(); }
process.on('SIGINT', interrupt);
process.on('SIGTERM', interrupt);

async function run(label, command, args, cwd, timeoutMs) {
  if (interrupted) throw new Error('Conformance interrupted');
  console.log(label);
  await new Promise((resolveRun, reject) => {
    child = spawn(command, args, { cwd, detached: true, stdio: 'ignore' });
    const timer = setTimeout(killOwned, timeoutMs);
    child.once('error', error => { clearTimeout(timer); reject(new Error(`${label}: ${error.code ?? 'startup failed'}`)); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      killOwned(); // No child/build process may outlive this bounded stage.
      child = undefined;
      if (code !== 0 || signal || interrupted) reject(new Error(`${label}: failed (exit ${code}, signal ${signal ?? 'none'})`));
      else resolveRun();
    });
  });
}
function admitted(path, runtime) {
  const report = JSON.parse(readFileSync(path, 'utf8'));
  if (report.runtime !== runtime || report.result !== 'PASS' || report.contractVersion !== '1.0.0'
      || report.schemaVersion !== '1.0.0' || !Number.isSafeInteger(report.summary?.total) || report.summary.total <= 0
      || report.summary.failed !== 0 || report.summary.passed !== report.summary.total
      || !Array.isArray(report.records) || report.records.length !== 0) throw new Error(`${runtime}: incomplete or failing conformance evidence`);
  return report;
}
try {
  mkdirSync(output, { recursive: true });
  // A failed later invocation must never leave the previous PASS as current.
  writeFileSync(summaryPath, JSON.stringify({ schema: 'hushvoting-public-dat-conformance-v1', result: 'RUNNING' }) + '\n');
  const manifestDigest = digest(join(corpus, 'manifest.json'));
  const vectorDigest = digest(join(corpus, 'vectors/dat-vectors.json'));
  const vectorCount = JSON.parse(readFileSync(join(corpus, 'vectors/dat-vectors.json'), 'utf8')).vectors.length;
  if (vectorCount !== 15) throw new Error('Public v1 DAT inventory requires explicit review');
  await run('Executing TypeScript production conformance', 'npm', ['run', 'identity:conformance'], repo, 90_000);
  const tsPath = join(repo, 'conformance/reports/typescript-identity-report.json');
  const ts = admitted(tsPath, 'typescript');
  writeFileSync(join(output, 'typescript.json'), readFileSync(tsPath));
  built = true;
  await run('Building the .NET conformance adapter', 'dotnet', ['build', project, '--no-restore', '--disable-build-servers', '--verbosity', 'quiet', '-warnaserror', '-p:UseSharedCompilation=false', '-nodeReuse:false'], server, 120_000);
  const netPath = join(output, 'dotnet.json');
  await run('Executing .NET conformance', 'dotnet', [assembly, '--corpus', corpus, '--manifest-digest', manifestDigest, '--report', netPath], server, 60_000);
  const net = admitted(netPath, 'dotnet');
  if (ts.summary.total !== net.summary.total || manifestDigest !== digest(join(corpus, 'manifest.json'))
      || vectorDigest !== digest(join(corpus, 'vectors/dat-vectors.json'))) throw new Error('Runtime inventory or corpus changed during execution');
  const evidence = { schema: 'hushvoting-public-dat-conformance-v1', result: 'PASS', publicDatVectors: vectorCount,
    fullCorpusChecksPerRuntime: ts.summary.total, manifestDigest, vectorDigest,
    scope: 'isolated public compatibility conformance; not browser/server or external qualification evidence' };
  writeFileSync(summaryPath, JSON.stringify(evidence, null, 2) + '\n');
  console.log(`FEAT-009: ${vectorCount} public DAT vectors executed in both runtimes; ${ts.summary.total} full-corpus checks each passed.`);
  console.log('Reports: conformance/reports/credential-file-restore/');
} catch (error) {
  try { writeFileSync(summaryPath, JSON.stringify({ schema: 'hushvoting-public-dat-conformance-v1', result: 'FAIL' }) + '\n'); } catch { /* preserve original failure */ }
  console.error(error.message);
  process.exitCode = 1;
} finally {
  killOwned();
  if (built && !interrupted) {
    try { await run('Shutting down .NET build servers', 'dotnet', ['build-server', 'shutdown'], server, 30_000); }
    catch {
      writeFileSync(summaryPath, JSON.stringify({ schema: 'hushvoting-public-dat-conformance-v1', result: 'FAIL' }) + '\n');
      process.exitCode = 1;
    }
  }
}
