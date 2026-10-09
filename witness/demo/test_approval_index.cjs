const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

const target = 'https://api.github.com/repos/octocat/Hello-World/issues?per_page=1&state=all&sort=created&direction=asc';
function element() {
  return {textContent:'', value:'', hidden:true, disabled:false, dataset:{}, children:[], listeners:{},
    addEventListener(name, fn) { this.listeners[name] = fn; },
    replaceChildren() { this.children = []; }, append(child) { this.children.push(child); }};
}
const drain = () => new Promise(resolve => setImmediate(resolve));
function harness(replies) {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script>\s*([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 2);
  const nodes = new Map();
  const document = {querySelector(selector) {
    if (!nodes.has(selector)) nodes.set(selector, element());
    return nodes.get(selector);
  }, createElement:element};
  const calls = [];
  const fetch = async (url, options) => {
    calls.push([url, options]);
    const next = replies.shift();
    assert.ok(next, `unexpected request: ${url}`);
    assert.equal(url, next[0]);
    return {ok:next[1] < 400, status:next[1], json:async () => next[2]};
  };
  const window = {setTimeout() { return 1; }, clearTimeout() {}, addEventListener() {}};
  vm.runInNewContext(scripts[1][1], {document, window, fetch, AbortController});
  return {nodes, calls};
}
const waiting = (scenario = 'confirm') => ({operation_id:'original-op', scenario,
  status:'waiting_for_review', choice:null, provider_attempts:0,
  review:{kind:scenario, id:'review-original', expires_at:'2026-10-10T00:00:00Z'}});
const status = job => ({lab_mode:'approval', ready:true, csrf_token:'loopback-csrf', target_url:target, jobs:[job]});

test('load restores a waiting operation without starting or dispatching it', async () => {
  const job = waiting();
  const replies = [['/api/approval-lab/status',200,status(job)], ['/api/approval-lab/jobs/original-op',200,job]];
  const {nodes,calls} = harness(replies);
  await drain();
  assert.equal(nodes.get('#approval-operation').textContent, 'original-op');
  assert.equal(nodes.get('#approval-attempts').textContent, '0');
  assert.equal(nodes.get('#approval-choices').hidden, false);
  assert.equal(nodes.get('#approval-start-confirm').disabled, true);
  assert.ok(calls.every(([,options]) => options.method === 'GET'));
  assert.equal(replies.length,0);
});

for (const scenario of ['confirm','escalate']) {
  test(`${scenario} approve hides buttons and continues original operation once`, async () => {
    const job = waiting(scenario);
    const continuing = {...job, choice:'approve', status:'continuing', choice_recorded:false};
    const succeeded = {...continuing, status:'succeeded', choice_recorded:true, final_decision:'allow', provider_attempts:1,
      provider_http_status:200, response_body:'[{"title":"public issue"}]'};
    const replies = [['/api/approval-lab/status',200,status(job)], ['/api/approval-lab/jobs/original-op',200,job],
      ['/api/approval-lab/jobs/original-op/resolve',202,continuing], ['/api/approval-lab/jobs/original-op',200,succeeded]];
    const {nodes,calls} = harness(replies);
    await drain();
    const click = nodes.get('#approval-approve').listeners.click();
    assert.equal(nodes.get('#approval-choices').hidden,true);
    assert.equal(nodes.get('#approval-refresh').disabled,true);
    await nodes.get('#approval-approve').listeners.click();
    await click;
    assert.equal(nodes.get('#approval-state').textContent,'succeeded');
    assert.equal(nodes.get('#approval-operation').textContent,'original-op');
    assert.equal(nodes.get('#approval-http').textContent,'HTTP 200');
    assert.equal(nodes.get('#approval-choices').hidden,true);
    assert.equal(calls.filter(([,options]) => options.method === 'POST').length,1);
    assert.equal(replies.length,0);
  });
}

test('reject reports recorded choice with no provider dispatch', async () => {
  const job = waiting('escalate');
  const rejected = {...job, choice:'reject', choice_recorded:true, status:'rejected', provider_attempts:0};
  const replies = [['/api/approval-lab/status',200,status(job)], ['/api/approval-lab/jobs/original-op',200,job],
    ['/api/approval-lab/jobs/original-op/resolve',202,rejected], ['/api/approval-lab/jobs/original-op',200,rejected]];
  const {nodes} = harness(replies);
  await drain();
  await nodes.get('#approval-reject').listeners.click();
  assert.equal(nodes.get('#approval-choice').textContent,'reject selected — recorded');
  assert.equal(nodes.get('#approval-attempts').textContent,'0');
  assert.equal(nodes.get('#approval-choices').hidden,true);
  assert.equal(replies.length,0);
});

test('external review restores and polls without exposing local decision buttons', async () => {
  const job = waiting('escalate');
  const replies = [['/api/approval-lab/status',200,{...status(job), external_review:true}],
    ['/api/approval-lab/jobs/original-op',200,job]];
  const {nodes,calls} = harness(replies);
  await drain();
  assert.equal(nodes.get('#approval-choices').hidden,true);
  assert.equal(nodes.get('#approval-approve').disabled,true);
  assert.equal(nodes.get('#approval-reject').disabled,true);
  assert.match(nodes.get('#approval-mode').textContent,/external review/);
  assert.match(nodes.get('#approval-description').textContent,/such as Slack/);
  assert.match(nodes.get('#approval-reviewer-note').textContent,/cannot approve or reject/);
  await nodes.get('#approval-approve').listeners.click();
  await nodes.get('#approval-reject').listeners.click();
  assert.ok(calls.every(([,options]) => options.method === 'GET'));
  assert.equal(nodes.get('#approval-operation').textContent,'original-op');
  assert.equal(nodes.get('#approval-attempts').textContent,'0');
  assert.equal(replies.length,0);
});
