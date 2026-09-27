// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/public/cpp/parsed_headers.h"

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <string>
#include <string_view>

#include <fuzzer/FuzzedDataProvider.h>

#include "base/at_exit.h"
#include "base/i18n/icu_util.h"
#include "base/no_destructor.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "url/gurl.h"

// PopulateParsedHeaders() is the single point where the network service runs
// every response-header parser over bytes the response's server fully
// controls. Fuzzing it exercises the whole set at once, including the parsers
// that have no fuzzer of their own (No-Vary-Search, Link, Integrity-Policy,
// Connection-Allowlist, Cookie-Indices, Supports-Loading-Mode, ...).

namespace {

struct Environment {
  Environment() { CHECK(base::i18n::InitializeICU()); }
  base::AtExitManager at_exit_manager;
};

// The response URL is a parser input too: Link and Connection-Allowlist
// resolve against it, and a few parsers key on the origin's scheme.
constexpr auto kUrls = std::to_array<const char*>({
    "https://example.test/index.html",
    "http://example.test/index.html",
    "https://sub.example.test:8443/a/b?q=1#f",
    "data:text/html,x",
    "about:blank",
});

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static const base::NoDestructor<Environment> environment;

  FuzzedDataProvider provider(data, size);
  const GURL url(kUrls.at(
      provider.ConsumeIntegralInRange<size_t>(0, kUrls.size() - 1)));

  // AssembleRawHeaders() is what the network stack applies to wire bytes
  // before constructing HttpResponseHeaders, so fuzzing through it keeps the
  // input space the same shape as a real response.
  const std::string raw = provider.ConsumeRemainingBytesAsString();
  auto headers = base::MakeRefCounted<net::HttpResponseHeaders>(
      net::HttpUtil::AssembleRawHeaders(raw));

  network::PopulateParsedHeaders(headers.get(), url);
  return 0;
}
