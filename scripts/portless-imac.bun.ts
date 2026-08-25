#!/usr/bin/env bun
// 用户原始需求（2026-08-12）：开发机用 Portless 测试远程 iMac 上的 iweb 节点。
// 正交意图：加载受管节点配置；远程启动容器；建立本机 TCP 转发；验证 Portless 多级域名入口。

import { $ } from "bun";

type CommandName = "up" | "connect";

interface Config {
  readonly baseHost: string;
  readonly remoteHost: string;
  readonly remotePort: number;
  readonly localForwardPort: number;
  readonly sshUser: string;
  readonly sshHost: string;
  readonly sshPort: number;
  readonly sshIdentityFile?: string;
  readonly dockerContext: string;
  readonly restartPortless: boolean;
}

const projectDir = new URL("..", import.meta.url).pathname;
const configPath = process.env.IWEB_PORTLESS_CONFIG ?? `${projectDir}/.env.portless-imac`;
const commandName = parseCommand(process.argv.slice(2));
let forwarder: Bun.Subprocess | undefined;

function parseCommand(args: readonly string[]): CommandName {
  const [command = "up"] = args;
  if ((command === "up" || command === "connect") && args.length === 1) return command;
  fail("usage: bun scripts/portless-imac.bun.ts [up|connect]");
}

async function loadConfig(path: string): Promise<Config> {
  const file = Bun.file(path);
  const values = (await file.exists()) ? parseEnvFile(await file.text(), path) : {};
  const read = (name: string, fallback?: string): string => {
    // Bun auto-loads the repository .env. The dedicated remote-development file must win.
    const value = values[name] ?? process.env[name] ?? fallback;
    if (!value) fail(`${name} is required; set it in ${path}`);
    return value;
  };
  const number = (name: string, fallback: string): number => {
    const value = Number(read(name, fallback));
    if (!Number.isInteger(value) || value < 1 || value > 65535) fail(`${name} must be a TCP port`);
    return value;
  };

  const baseHost = read("IWEB_BASE_HOST", "test.iweb.localhost").toLowerCase().replace(/\.$/, "");
  if (!baseHost.endsWith(".localhost") || baseHost === ".localhost") {
    fail("IWEB_BASE_HOST must end in .localhost for Portless");
  }

  return {
    baseHost,
    remoteHost: read("IWEB_REMOTE_HOST", "192.168.2.13"),
    remotePort: number("IWEB_REMOTE_PORT", "9010"),
    localForwardPort: number("IWEB_LOCAL_FORWARD_PORT", "19010"),
    sshUser: read("IWEB_SSH_USER", "kzf"),
    sshHost: read("IWEB_SSH_HOST", "bngjdemac-mini-7.local"),
    sshPort: number("IWEB_SSH_PORT", "22"),
    sshIdentityFile: values.IWEB_SSH_IDENTITY_FILE ?? process.env.IWEB_SSH_IDENTITY_FILE,
    dockerContext: read("IWEB_DOCKER_CONTEXT", "remote-mini"),
    restartPortless: (process.env.IWEB_PORTLESS_RESTART ?? values.IWEB_PORTLESS_RESTART ?? "1") === "1",
  };
}

function parseEnvFile(source: string, path: string): Readonly<Record<string, string>> {
  const entries = source.split(/\r?\n/).flatMap((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return [];
    const separator = trimmed.indexOf("=");
    if (separator < 1) fail(`invalid environment assignment in ${path}`);
    return [[trimmed.slice(0, separator).trim(), trimmed.slice(separator + 1).trim()] as const];
  });
  return Object.fromEntries(entries);
}

function fail(message: string): never {
  forwarder?.kill();
  console.error(`iweb portless: ${message}`);
  process.exit(1);
}

async function run(command: readonly string[], options: { readonly quiet?: boolean; readonly allowFailure?: boolean } = {}): Promise<string> {
  const commandLine = $`${command}`.cwd(projectDir);
  const result = await (options.allowFailure ? commandLine.nothrow() : commandLine).quiet();
  const output = result.text().trim();
  if (!options.allowFailure && result.exitCode !== 0) fail(output || `${command[0]} failed`);
  if (!options.quiet && output) console.log(output);
  return output;
}

async function main(): Promise<void> {
  const config = await loadConfig(configPath);
  await ensureCommand("portless");
  await ensureCommand("curl");
  await ensureCommand("ssh");

  if (commandName === "up") await deployRemoteNode(config);
  const ownsForwarder = await startForwarder(config);
  await waitForRemoteHealth(config);
  await registerPortlessAliases(config);
  console.log("iweb portless: skipping optional hosts sync; run `sudo portless hosts sync` only if Safari cannot resolve nested .localhost names");
  await ensureWildcardProxy(config);
  await verifyIngress(config);

  console.log(`\niweb Portless ingress is ready. Keep this terminal open while testing.\n\nRemote node: ${config.remoteHost}:${config.remotePort}\nLocal forward: 127.0.0.1:${config.localForwardPort}\nBase host: ${config.baseHost}\n\nhttps://${config.baseHost}/\nhttps://admin.${config.baseHost}/\nhttps://api.${config.baseHost}/v1/status\nhttps://notes.app.${config.baseHost}/\nhttps://hello.${config.baseHost}/\nhttps://search.${config.baseHost}/\nhttps://collab.${config.baseHost}/\nhttps://collab-b.${config.baseHost}/\nhttps://${config.baseHost}/notes/app`);

  if (ownsForwarder) {
    await forwarder?.exited;
    fail("SSH forwarder stopped");
  }
  await waitForTermination();
}

async function ensureCommand(command: string): Promise<void> {
  const output = await run(["command", "-v", command], { allowFailure: true, quiet: true });
  if (!output) fail(`${command} is required`);
}

async function deployRemoteNode(config: Config): Promise<void> {
  await ensureCommand("docker");
  if (!(await Bun.file(`${projectDir}/.env`).exists())) fail(`${projectDir}/.env is required to deploy the remote node`);

  console.log(`iweb portless: building and starting iweb through Docker context ${config.dockerContext}`);
  const result = await $`docker --context ${config.dockerContext} compose -f ${projectDir}/docker-compose.yml -f ${projectDir}/docker-compose.portless.yml up --detach --build`
    .cwd(projectDir)
    .env({ ...process.env, IWEB_PORTLESS_BASE_HOST: config.baseHost })
    .quiet();
  const output = result.text().trim();
  if (result.exitCode !== 0) fail(output || "remote Docker deployment failed");
  if (output) console.log(output);
}

async function startForwarder(config: Config): Promise<boolean> {
  if (await localHealthIsReady(config)) {
    console.log(`iweb portless: reusing healthy local forward on 127.0.0.1:${config.localForwardPort}`);
    return false;
  }

  const arguments_ = [
    "-N",
    "-T",
    "-p",
    String(config.sshPort),
    "-o",
    "ExitOnForwardFailure=yes",
    "-o",
    "ServerAliveInterval=30",
    "-o",
    "ServerAliveCountMax=3",
    "-L",
    `127.0.0.1:${config.localForwardPort}:127.0.0.1:${config.remotePort}`,
  ];
  if (config.sshIdentityFile) arguments_.push("-i", config.sshIdentityFile);
  arguments_.push(`${config.sshUser}@${config.sshHost}`);
  forwarder = Bun.spawn(["ssh", ...arguments_], { cwd: projectDir, stdin: "ignore", stdout: "inherit", stderr: "inherit" });
  await Bun.sleep(250);
  if (forwarder.exitCode !== null) {
    fail(`SSH forwarder stopped before becoming ready; check whether 127.0.0.1:${config.localForwardPort} is already in use`);
  }
  return true;
}

async function waitForRemoteHealth(config: Config): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (forwarder && forwarder.exitCode !== null) {
      fail(`SSH forwarder stopped before becoming ready; check whether 127.0.0.1:${config.localForwardPort} is already in use`);
    }
    if (await localHealthIsReady(config)) return;
    await Bun.sleep(250);
  }
  fail(`cannot reach iweb at ${config.remoteHost}:${config.remotePort} through local port ${config.localForwardPort}`);
}

async function localHealthIsReady(config: Config): Promise<boolean> {
  const result = await $`curl --noproxy ${"*"} --silent --fail --connect-timeout 1 -H ${`Host: ${config.baseHost}`} http://127.0.0.1:${config.localForwardPort}/_iweb/health`
    .cwd(projectDir)
    .nothrow()
    .quiet();
  return result.exitCode === 0 && result.text().trim() === "ok";
}

async function ensureWildcardProxy(config: Config): Promise<void> {
  if ((await httpsStatus(`admin.${config.baseHost}`, "/")) === "200") return;
  if (!config.restartPortless) {
    fail("Portless wildcard routing is inactive: https://admin.<base> did not reach iweb");
  }

  console.log("iweb portless: restarting Portless in wildcard mode");
  const stateDir = `${process.env.HOME ?? fail("HOME is required")}/.portless`;
  await runInteractive(
    ["sudo", "env", `PORTLESS_STATE_DIR=${stateDir}`, "portless", "proxy", "stop"],
    "cannot stop the existing Portless proxy. Run this script from a terminal that can answer the macOS sudo prompt",
  );
  await runInteractive(["env", `PORTLESS_STATE_DIR=${stateDir}`, "portless", "proxy", "start", "--wildcard"], "cannot start Portless wildcard proxy");

  for (let attempt = 0; attempt < 20; attempt += 1) {
    if ((await httpsStatus(`admin.${config.baseHost}`, "/")) === "200") return;
    await Bun.sleep(250);
  }
  fail("Portless restarted but https://admin.<base> still did not reach iweb");
}

async function runInteractive(command: readonly string[], failureMessage: string): Promise<void> {
  const process = Bun.spawn(command, { cwd: projectDir, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
  if ((await process.exited) !== 0) fail(failureMessage);
}

function portlessName(config: Config): string {
  return config.baseHost.slice(0, -".localhost".length);
}

async function registerPortlessAliases(config: Config): Promise<void> {
  // typescript-monorepo：已知 host 覆盖过渡 fleet 全部应用（hello/search/collab/collab-b）。
  const names = [
    portlessName(config),
    `admin.${portlessName(config)}`,
    `api.${portlessName(config)}`,
    `mcp.${portlessName(config)}`,
    `admin.app.${portlessName(config)}`,
    `notes.app.${portlessName(config)}`,
    `hello.${portlessName(config)}`,
    `search.${portlessName(config)}`,
    `collab.${portlessName(config)}`,
    `collab-b.${portlessName(config)}`,
  ];

  for (const name of names) {
    await run(["portless", "alias", name, String(config.localForwardPort), "--force"]);
  }
}

async function verifyIngress(config: Config): Promise<void> {
  // notes.app intentionally expects 502: a registered user application without
  // a ready active sandbox MUST return a generic 502 and never fall back to the
  // shared Dispatcher (isolate-untrusted-applications). It becomes 200 only
  // after Notes is migrated to a sandboxed version. mcp rejects a plain GET of
  // the JSON-RPC endpoint with 405. The bare base host is 404: the Rust kernel
  // serves public workspace objects only through the IWEB_PUBLIC_OBJECTS
  // whitelist, and the dev deployment declares none (fail closed).
  const probes: ReadonlyArray<readonly [hostname: string, path: string, expectedStatus: number]> = [
    [config.baseHost, "/", 404],
    [`admin.${config.baseHost}`, "/", 200],
    [`api.${config.baseHost}`, "/v1/status", 401],
    [`notes.app.${config.baseHost}`, "/", 502],
    [config.baseHost, "/notes/app", 502],
    [`mcp.${config.baseHost}`, "/mcp", 405],
    [`hello.${config.baseHost}`, "/", 200],
    [`search.${config.baseHost}`, "/", 200],
    [`collab.${config.baseHost}`, "/", 200],
    [`collab-b.${config.baseHost}`, "/", 200],
  ];
  for (const [host, path, expectedStatus] of probes) {
    const actualStatus = await httpsStatus(host, path);
    if (actualStatus !== String(expectedStatus)) {
      fail(`Portless probe failed for https://${host}${path}: expected ${expectedStatus}, received ${actualStatus || "connection failure"}`);
    }
  }
}

async function httpsStatus(host: string, path: string): Promise<string> {
  const result = await $`curl --noproxy ${"*"} --silent --output /dev/null --write-out ${"%{http_code}"} --connect-timeout 3 https://${host}${path}`
    .cwd(projectDir)
    .nothrow()
    .quiet();
  return result.text().trim();
}

async function waitForTermination(): Promise<void> {
  await new Promise<void>((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    forwarder?.kill();
    process.exit(0);
  });
}

void main();
