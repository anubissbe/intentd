const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const { runInNewContext } = require('node:vm');

const workflow = readFileSync(join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
const script = workflow.match(/          script: \|\n((?:            .*\n|\n)+)/)[1];

async function route(owner, runners = []) {
  const outputs = {};
  let probes = 0;
  await runInNewContext(`(async () => { ${script} })()`, {
    context: { repo: { owner, repo: 'intentd' }, runId: 1 },
    process: { env: {} },
    core: { info() {}, setOutput: (name, value) => { outputs[name] = value; } },
    github: {
      paginate: async () => {
        probes++;
        if (runners instanceof Error) throw runners;
        return runners;
      },
      rest: { actions: {
        listSelfHostedRunnersForOrg() {},
        listSelfHostedRunnersForRepo() {},
        listWorkflowRunsForRepo: async () => ({ data: { workflow_runs: [] } }),
      } },
    },
  });
  return { outputs, probes };
}

test('forks use accessible hosted runners without probing Intent infrastructure', async () => {
  const { outputs, probes } = await route('anubissbe');
  assert.deepEqual(JSON.parse(outputs.check_labels), ['ubuntu-latest']);
  assert.deepEqual(JSON.parse(outputs.linux_labels), ['ubuntu-latest']);
  assert.deepEqual(JSON.parse(outputs.windows_labels), ['windows-latest']);
  assert.equal(outputs.linux_burst, 'true');
  assert.equal(outputs.windows_burst, 'true');
  assert.equal(probes, 0);
});

test('upstream still bursts to its larger runners when the probe fails', async () => {
  const { outputs } = await route('intent-hq', new Error('permission denied'));
  assert.deepEqual(JSON.parse(outputs.check_labels), ['gh-linux-8x']);
  assert.deepEqual(JSON.parse(outputs.linux_labels), ['gh-linux-16x']);
  assert.deepEqual(JSON.parse(outputs.windows_labels), ['gh-windows-16x']);
});

test('upstream still selects healthy self-hosted Linux and Windows runners', async () => {
  const runners = ['Linux', 'Windows'].map(os => ({
    status: 'online', labels: ['self-hosted', os, 'X64'].map(name => ({ name })),
  }));
  const { outputs } = await route('intent-hq', runners);
  assert.deepEqual(JSON.parse(outputs.linux_labels), ['self-hosted', 'Linux', 'X64']);
  assert.deepEqual(JSON.parse(outputs.windows_labels), ['self-hosted', 'Windows', 'X64']);
  assert.equal(outputs.linux_burst, 'false');
  assert.equal(outputs.windows_burst, 'false');
});
