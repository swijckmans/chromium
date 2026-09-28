// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/public/cpp/sri_message_signatures.h"

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/i18n/icu_util.h"
#include "base/no_destructor.h"
#include "base/strings/string_split.h"
#include "base/test/task_environment.h"
#include "base/test/test_timeouts.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "services/network/public/cpp/integrity_metadata.h"
#include "services/network/public/mojom/integrity_algorithm.mojom.h"
#include "services/network/public/mojom/unencoded_digest.mojom.h"
#include "url/gurl.h"

namespace {

struct Environment {
  Environment() {
    base::CommandLine::Init(0, nullptr);
    TestTimeouts::Initialize();
    task_environment = std::make_unique<base::test::TaskEnvironment>(
        base::test::TaskEnvironment::MainThreadType::IO);
    CHECK(base::i18n::InitializeICU());
    context = net::CreateTestURLRequestContextBuilder()->Build();
  }

  base::AtExitManager at_exit_manager;
  std::unique_ptr<base::test::TaskEnvironment> task_environment;
  std::unique_ptr<net::URLRequestContext> context;
};

constexpr auto kUrls = std::to_array<const char*>({
    "https://example.test/a/b?q=1&r=2",
    "https://example.test:8443/x?name=v",
    "http://example.test/",
    "https://u:p@example.test/p?q#frag",
});

constexpr auto kMethods = std::to_array<const char*>({"GET", "POST", "HEAD"});

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static const base::NoDestructor<Environment> environment;

  FuzzedDataProvider provider(data, size);
  const GURL url(
      kUrls.at(provider.ConsumeIntegralInRange<size_t>(0, kUrls.size() - 1)));
  const std::string method =
      kMethods.at(provider.ConsumeIntegralInRange<size_t>(
          0, kMethods.size() - 1));

  net::TestDelegate delegate;
  std::unique_ptr<net::URLRequest> request = environment->context->CreateRequest(
      url, net::DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS,
      net::handles::kInvalidNetworkHandle);
  request->set_method(method);

  net::HttpRequestHeaders request_headers;
  const std::string raw_request_headers = provider.ConsumeRandomLengthString();
  for (std::string_view line :
       base::SplitStringPiece(raw_request_headers, "\n", base::KEEP_WHITESPACE,
                              base::SPLIT_WANT_NONEMPTY)) {
    line = net::HttpUtil::TrimLWS(line);
    const size_t separator = line.find(':');
    if (separator == std::string_view::npos) {
      continue;
    }
    const std::string_view key =
        net::HttpUtil::TrimLWS(line.substr(0, separator));
    const std::string_view value =
        net::HttpUtil::TrimLWS(line.substr(separator + 1));
    if (net::HttpUtil::IsValidHeaderName(key) &&
        net::HttpUtil::IsValidHeaderValue(value)) {
      request_headers.SetHeader(key, value);
    }
  }
  request->SetExtraRequestHeaders(request_headers);

  std::vector<std::vector<uint8_t>> expected_public_keys;
  if (provider.ConsumeBool()) {
    std::vector<uint8_t> key = provider.ConsumeBytes<uint8_t>(32);
    key.resize(32);
    expected_public_keys.push_back(std::move(key));
  }

  const bool add_digest = provider.ConsumeBool();
  auto response = network::mojom::URLResponseHead::New();
  response->headers = base::MakeRefCounted<net::HttpResponseHeaders>(
      net::HttpUtil::AssembleRawHeaders(
          provider.ConsumeRemainingBytesAsString()));
  if (add_digest) {
    response->unencoded_digests = network::mojom::UnencodedDigests::New();
    response->unencoded_digests->digests.emplace_back(
        network::IntegrityMetadata(network::mojom::IntegrityAlgorithm::kSha256,
                                   std::vector<uint8_t>(32)));
  }

  network::mojom::SRIMessageSignaturesPtr parsed =
      network::ParseSRIMessageSignaturesFromHeaders(*response->headers);
  network::ValidateSRIMessageSignaturesOverHeaders(parsed, *request,
                                                   *response->headers);
  network::MaybeBlockResponseForSRIMessageSignature(
      *request, *response, expected_public_keys, nullptr, "");
  network::MaybeSetAcceptSignatureHeader(request.get(), expected_public_keys);
  return 0;
}
