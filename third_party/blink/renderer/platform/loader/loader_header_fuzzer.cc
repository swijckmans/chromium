// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <string>

#include "base/containers/span.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/integrity_report.h"
#include "third_party/blink/renderer/platform/loader/link_header.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/fuzzed_data_provider.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

String Latin1String(const String& value) {
  return String(value.Latin1());
}

void ExerciseLinkHeader(const String& fuzzed_header) {
  LinkHeaderSet headers(Latin1String(fuzzed_header));
  for (const LinkHeader& header : headers) {
    header.Url();
    header.Rel();
    header.As();
    header.MimeType();
    header.Media();
    header.CrossOrigin();
    header.Nonce();
    header.Integrity();
    header.ImageSrcset();
    header.ImageSizes();
    header.HeaderIntegrity();
    header.Variants();
    header.VariantKey();
    header.Blocking();
    header.ReferrerPolicy();
    header.FetchPriority();
    header.Anchor();
    header.Valid();
    header.IsViewportDependent();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support;
  static test::TaskEnvironment task_environment;
  FuzzedDataProvider provider(data, size);

  ExerciseLinkHeader(provider.ConsumeRandomLengthString(512));

  IntegrityMetadataSet metadata;
  String integrity_attribute = provider.ConsumeRandomLengthString(512);
  IntegrityReport integrity_report;
  SubresourceIntegrity::ParseIntegrityAttribute(
      integrity_attribute, metadata, /*feature_context=*/nullptr,
      &integrity_report);

  ScopedSignatureBasedInlineIntegrityForTest inline_integrity(true);
  SubresourceIntegrity::VerifyInlineIntegrity(
      integrity_attribute, provider.ConsumeRandomLengthString(512),
      provider.ConsumeRandomLengthString(512), /*feature_context=*/nullptr);

  String fuzzed_url = provider.ConsumeRandomLengthString(512);
  KURL resource_url(fuzzed_url);
  if (!resource_url.IsValid()) {
    resource_url = KURL("https://example.test/resource");
  }

  String raw_header_lines = provider.ConsumeRandomLengthString(1024);
  String raw_headers = "HTTP/1.1 200 OK\r\n" + Latin1String(raw_header_lines) +
                       "\r\n\r\n";
  std::string body = provider.ConsumeRemainingBytes();
  SegmentedBuffer buffer;
  buffer.Append(base::as_byte_span(body));

  constexpr network::mojom::blink::FetchResponseType kResponseTypes[] = {
      network::mojom::blink::FetchResponseType::kBasic,
      network::mojom::blink::FetchResponseType::kCors,
      network::mojom::blink::FetchResponseType::kDefault,
      network::mojom::blink::FetchResponseType::kError,
      network::mojom::blink::FetchResponseType::kOpaque,
      network::mojom::blink::FetchResponseType::kOpaqueRedirect,
  };
  const auto response_type = provider.PickValueInArray(kResponseTypes);
  IntegrityReport response_report;
  SubresourceIntegrity::CheckSubresourceIntegrity(
      metadata, &buffer, resource_url, response_type, raw_headers,
      /*feature_context=*/nullptr, response_report);
  return 0;
}

}  // namespace blink
