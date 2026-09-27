// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <array>
#include <memory>
#include <string>
#include <string_view>

#include "base/types/expected.h"
#include "components/url_pattern/simple_url_pattern_matcher.h"
#include "url/gurl.h"

namespace url_pattern {
namespace {

// Fuzzes SimpleUrlPatternMatcher::Create() with an attacker-controlled
// constructor string. In production this string comes straight from the
// `match=` member of a server-sent `Use-As-Dictionary` response header and is
// parsed inside the network service, so every byte is remote-controlled.
constexpr std::array<std::string_view, 7> kBaseUrls = {
    "https://example.com/dir/dict.dat",
    "https://user:pw@example.com:8443/a/b/c?x=1#frag",
    "http://[::1]:8080/path",
    "file:///tmp/dict",
    "data:text/plain,hello",
    "foo://opaque:path/x",
    "https://xn--nxasmq6b.example/%E2%82%AC",
};

}  // namespace
}  // namespace url_pattern

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  using url_pattern::kBaseUrls;
  using url_pattern::SimpleUrlPatternMatcher;
  FuzzedDataProvider fdp(data, size);

  const bool use_base_url = fdp.ConsumeBool();
  const size_t base_index =
      fdp.ConsumeIntegralInRange<size_t>(0, std::size(kBaseUrls) - 1);
  const std::string probe_url_string = fdp.ConsumeRandomLengthString(256);
  const std::string constructor_string = fdp.ConsumeRemainingBytesAsString();

  GURL base_url(kBaseUrls.at(base_index));
  auto result = SimpleUrlPatternMatcher::Create(
      constructor_string, use_base_url ? &base_url : nullptr);
  if (!result.has_value()) {
    return 0;
  }

  std::unique_ptr<SimpleUrlPatternMatcher> matcher = std::move(result.value());
  for (std::string_view base : kBaseUrls) {
    GURL url(base);
    matcher->Match(url);
    matcher->HostOnlyMatch(url);
  }
  GURL probe(probe_url_string);
  if (probe.is_valid()) {
    matcher->Match(probe);
    matcher->HostOnlyMatch(probe);
  }
  GURL relative = base_url.Resolve(probe_url_string);
  if (relative.is_valid()) {
    matcher->Match(relative);
  }
  return 0;
}
