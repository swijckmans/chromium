// META: script=/common/get-host-info.sub.js
// META: script=/service-workers/service-worker/resources/test-helpers.sub.js
// META: script=/resources/testdriver.js
// META: script=/resources/testdriver-vendor.js

'use strict';

async function registerBackgroundFetch(test, scopeName) {
  await test_driver.set_permission({name: 'background-fetch'}, 'granted');

  const registration = await service_worker_unregister_and_register(
      test, 'resources/service-worker-fetch-script.js',
      `resources/background-fetch-${scopeName}-scope/`);
  test.add_cleanup(() => registration.unregister());
  await wait_for_state(test, registration.installing, 'activated');
  return registration.backgroundFetch;
}

promise_test(async test => {
  const backgroundFetch =
      await registerBackgroundFetch(test, 'same-origin');
  const url = '/common/blank-with-cors.html';
  const registration =
      await backgroundFetch.fetch(crypto.randomUUID(), url);
  const record = await registration.match(url);

  assert_not_equals(record, null);
  const response = await record.responseReady;
  assert_equals(response.status, 200);
}, 'Background Fetch may request a same-origin URL in its allowlist.');

promise_test(async test => {
  const backgroundFetch =
      await registerBackgroundFetch(test, 'cross-origin');
  const url =
      `https://{{hosts[alt][]}}${get_host_info().HTTPS_PORT_ELIDED}` +
      '/common/blank-with-cors.html';
  const registration =
      await backgroundFetch.fetch(crypto.randomUUID(), url);
  const record = await registration.match(url);

  assert_not_equals(record, null);
  await promise_rejects_js(test, TypeError, record.responseReady);
}, 'Background Fetch cannot request a cross-origin URL outside its allowlist.');
