// META: script=/common/get-host-info.sub.js
// META: script=/common/utils.js
// META: script=resources/utils.js

promise_test(async t => {
  const key = token();
  const target =
      `http://{{hosts[alt][]}}:{{ports[http][0]}}/connection-allowlist/tentative/` +
      `resources/key-value-store.py?key=${key}&value=reached`;
  const link = document.createElement('a');
  link.download = 'x.txt';
  link.href = '/common/redirect.py?status=302&location=' +
      encodeURIComponent(target);
  document.body.appendChild(link);
  link.click();

  await new Promise(resolve => t.step_timeout(resolve, 3000));
  const {status} = await readValueFromServer(key);
  assert_false(status, 'The cross-origin download redirect should be blocked.');
}, 'Connection-Allowlist blocks renderer-initiated download redirects');
