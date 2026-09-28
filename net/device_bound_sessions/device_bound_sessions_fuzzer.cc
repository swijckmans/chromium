// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "base/memory/scoped_refptr.h"
#include "base/strings/strcat.h"
#include "net/device_bound_sessions/proto/storage.pb.h"
#include "net/device_bound_sessions/registration_fetcher_param.h"
#include "net/device_bound_sessions/session.h"
#include "net/device_bound_sessions/session_challenge_param.h"
#include "net/device_bound_sessions/session_inclusion_rules.h"
#include "net/device_bound_sessions/session_json_utils.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "url/gurl.h"

namespace {

constexpr auto kUrls = std::to_array<const char*>({
    "https://example.test/login",
    "https://a.example.test/x/y?z=1",
    "https://example.test:8443/",
    "http://example.test/",
    "https://sub.co.uk/",
    "https://[::1]/",
});

scoped_refptr<net::HttpResponseHeaders> CreateHeaders(
    std::string_view name,
    std::string_view value) {
  return base::MakeRefCounted<net::HttpResponseHeaders>(
      net::HttpUtil::AssembleRawHeaders(
          base::StrCat({"HTTP/1.1 200 OK\r\n", name, ": ", value, "\r\n\r\n"})));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);
  const GURL url(
      kUrls.at(provider.ConsumeIntegralInRange<size_t>(0, kUrls.size() - 1)));

  const bool restrict_to_site = provider.ConsumeBool();
  const std::vector<net::SchemefulSite> restricted_sites =
      restrict_to_site ? std::vector<net::SchemefulSite>{
                             net::SchemefulSite(url)}
                       : std::vector<net::SchemefulSite>();

  const std::string registration_value =
      provider.ConsumeRandomLengthString(512);
  scoped_refptr<net::HttpResponseHeaders> registration_headers = CreateHeaders(
      "Secure-Session-Registration", registration_value);
  net::device_bound_sessions::RegistrationFetcherParam::CreateIfValid(
      url, registration_headers.get(), restricted_sites);

  const std::string challenge_value = provider.ConsumeRandomLengthString(512);
  scoped_refptr<net::HttpResponseHeaders> challenge_headers =
      CreateHeaders("Secure-Session-Challenge", challenge_value);
  net::device_bound_sessions::SessionChallengeParam::CreateIfValid(
      url, challenge_headers.get());

  std::optional<std::string> expected_session_id;
  if (provider.ConsumeBool()) {
    expected_session_id = "sid";
  }
  const std::string json = provider.ConsumeRemainingBytesAsString();
  auto params = net::device_bound_sessions::ParseSessionInstructionJson(
      url, expected_session_id, json);
  if (params.has_value()) {
    auto session =
        net::device_bound_sessions::Session::CreateIfValid(*params);
    if (session.has_value()) {
      for (const char* url_string : kUrls) {
        (*session)->IncludesUrl(GURL(url_string));
      }
      (*session)->IncludesUrl(url);

      net::device_bound_sessions::proto::Session proto = (*session)->ToProto();
      auto restored =
          net::device_bound_sessions::Session::CreateFromProto(proto);
      if (restored.has_value()) {
        (*restored)->IncludesUrl(url);
        (*session)->IsEqualForTesting(**restored);
      }

      auto rules =
          net::device_bound_sessions::SessionInclusionRules::CreateFromProto(
              proto.session_inclusion_rules());
      if (rules.has_value()) {
        for (const char* url_string : kUrls) {
          rules->EvaluateRequestUrl(GURL(url_string));
        }
        rules->EvaluateRequestUrl(url);
      }
    }
  }

  net::device_bound_sessions::ParseWellKnownJson(json);
  return 0;
}
