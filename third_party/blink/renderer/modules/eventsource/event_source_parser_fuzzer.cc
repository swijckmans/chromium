// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <vector>

#include "base/containers/span.h"
#include "third_party/blink/renderer/modules/eventsource/event_source_parser.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/fuzzed_data_provider.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

class FuzzerClient final : public GarbageCollected<FuzzerClient>,
                           public EventSourceParser::Client {
 public:
  void OnMessageEvent(const AtomicString&,
                      const String&,
                      const AtomicString&) override {}
  void OnReconnectionTimeSet(uint64_t) override {}
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support;
  static test::TaskEnvironment task_environment;
  FuzzedDataProvider provider(data, size);

  Persistent<FuzzerClient> client = MakeGarbageCollected<FuzzerClient>();
  Persistent<EventSourceParser> parser = MakeGarbageCollected<EventSourceParser>(
      AtomicString(provider.ConsumeRandomLengthString(128)), client);
  std::vector<char> bytes = provider.ConsumeRemainingBytesAs<char>();
  size_t offset = 0;
  while (offset < bytes.size()) {
    const size_t chunk_size = provider.ConsumeIntegralInRange<size_t>(
        1, std::min<size_t>(64, bytes.size() - offset));
    parser->AddBytes(base::span(bytes).subspan(offset, chunk_size));
    offset += chunk_size;
    if (provider.ConsumeBool()) {
      parser->Stop();
    }
  }
  parser->LastEventId();
  return 0;
}

}  // namespace blink
