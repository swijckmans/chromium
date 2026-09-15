// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/webtransport/web_transport_connector_impl.h"

#include <memory>
#include <optional>

#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "content/browser/renderer_host/render_frame_host_impl.h"
#include "content/public/test/test_renderer_host.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/test_support/test_utils.h"
#include "net/http/http_request_headers.h"
#include "services/network/public/mojom/web_transport.mojom.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/webtransport/web_transport_connector.mojom.h"
#include "url/gurl.h"

namespace content {

namespace {

using Header = net::HttpRequestHeaders::HeaderKeyValuePair;

class WebTransportConnectorImplTest
    : public RenderViewHostTestHarness,
      public testing::WithParamInterface<Header> {
 protected:
  void SetUp() override {
    RenderViewHostTestHarness::SetUp();
    NavigateAndCommit(GURL("https://example.test/"));
  }

  void Connect(Header header) {
    auto* rfh = static_cast<RenderFrameHostImpl*>(main_rfh());
    mojo::Remote<blink::mojom::WebTransportConnector> connector;
    mojo::MakeSelfOwnedReceiver(
        std::make_unique<WebTransportConnectorImpl>(
            /*process_id=*/-1, rfh->GetWeakPtr(), rfh->GetWeakDocumentPtr(),
            rfh->GetLastCommittedOrigin(),
            rfh->GetIsolationInfoForSubresources()
                .network_anonymization_key(),
            rfh->BuildClientSecurityState(), rfh->GetNetworkRestrictionsID()),
        connector.BindNewPipeAndPassReceiver());
    mojo::PendingRemote<network::mojom::WebTransportHandshakeClient>
        handshake_client;
    [[maybe_unused]] mojo::PendingReceiver<
        network::mojom::WebTransportHandshakeClient>
        handshake_receiver = handshake_client.InitWithNewPipeAndPassReceiver();

    connector->Connect(
        GURL("https://example.test/"), /*fingerprints=*/{},
        /*application_protocols=*/{},
        network::mojom::WebTransportCongestionControl::kDefault,
        /*anticipated_concurrent_incoming_unidirectional_streams=*/std::nullopt,
        /*anticipated_concurrent_incoming_bidirectional_streams=*/std::nullopt,
        {std::move(header)}, std::move(handshake_client));
    base::RunLoop().RunUntilIdle();
  }
};

TEST_P(WebTransportConnectorImplTest, ForbiddenAdditionalHeaderIsBadMessage) {
  mojo::test::BadMessageObserver bad_message_observer;
  Connect(GetParam());
  EXPECT_EQ(
      bad_message_observer.WaitForBadMessage(),
      "Validation failed for blink.mojom.WebTransportConnector.0  "
      "[VALIDATION_ERROR_DESERIALIZATION_FAILED]");
}

INSTANTIATE_TEST_SUITE_P(
    All,
    WebTransportConnectorImplTest,
    ::testing::Values(Header("origin", "https://evil.test"),
                      Header(":authority", "x"), Header("sec-foo", "1"),
                      Header("host", "evil.test")),
    [](const testing::TestParamInfo<Header>& info) {
      return "Case" + base::NumberToString(info.index);
    });

TEST_F(WebTransportConnectorImplTest,
       NetworkUnsafeAdditionalHeaderIsBadMessage) {
  mojo::test::BadMessageObserver bad_message_observer;
  Connect(Header("available-dictionary", ":hash:"));
  EXPECT_EQ(bad_message_observer.WaitForBadMessage(),
            "WebTransportConnector: forbidden or invalid additional header");
}

TEST_F(WebTransportConnectorImplTest, BenignAdditionalHeaderIsNotBadMessage) {
  mojo::test::BadMessageObserver bad_message_observer;
  Connect(Header("x-custom", "v"));
  EXPECT_FALSE(bad_message_observer.got_bad_message());
}

}  // namespace

}  // namespace content
