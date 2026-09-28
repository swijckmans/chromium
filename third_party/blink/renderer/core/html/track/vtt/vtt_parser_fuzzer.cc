// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "base/containers/span.h"
#include "testing/libfuzzer/libfuzzer_base_wrappers.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_align_setting.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_direction_setting.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_setting.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_autokeyword_double.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/track/text_track.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_cue.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_parser.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_region.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/fuzzed_data_provider.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

class FuzzerParserClient final : public GarbageCollected<FuzzerParserClient>,
                                 public VTTParserClient {
 public:
  void NewCuesParsed() override { ++new_cues_notifications_; }
  void FileFailedToParse() override { parse_failed_ = true; }

  void Trace(Visitor* visitor) const override {
    VTTParserClient::Trace(visitor);
  }

  unsigned new_cues_notifications() const {
    return new_cues_notifications_;
  }
  bool parse_failed() const { return parse_failed_; }

 private:
  unsigned new_cues_notifications_ = 0;
  bool parse_failed_ = false;
};

void ExerciseRegion(VTTRegion& region,
                    Document& document,
                    FuzzedDataProvider& choices) {
  DummyExceptionStateForTesting exception_state;
  region.setWidth(choices.ConsumeIntegralInRange<int>(0, 100),
                  exception_state);
  region.setLines(choices.ConsumeIntegralInRange<unsigned>(0, 64));
  region.setRegionAnchorX(choices.ConsumeIntegralInRange<int>(-100, 200),
                          exception_state);
  region.setRegionAnchorY(choices.ConsumeIntegralInRange<int>(-100, 200),
                          exception_state);
  region.setViewportAnchorX(choices.ConsumeIntegralInRange<int>(-100, 200),
                            exception_state);
  region.setViewportAnchorY(choices.ConsumeIntegralInRange<int>(-100, 200),
                            exception_state);
  region.setScroll(V8ScrollSetting(
      choices.ConsumeBool() ? V8ScrollSetting::Enum::kUp
                            : V8ScrollSetting::Enum::k));
  region.GetDisplayTree(document);
}

void ExerciseCue(VTTCue& cue,
                 HTMLDivElement& container,
                 VTTRegion* region,
                 FuzzedDataProvider& choices) {
  cue.getCueAsHTML();
  cue.text();

  DummyExceptionStateForTesting exception_state;
  auto* line = MakeGarbageCollected<V8UnionAutoKeywordOrDouble>(
      choices.ConsumeIntegralInRange<int>(-100, 200));
  auto* position = MakeGarbageCollected<V8UnionAutoKeywordOrDouble>(
      choices.ConsumeIntegralInRange<int>(-100, 200));
  cue.setLine(line);
  cue.setPosition(position, exception_state);
  cue.setSize(choices.ConsumeIntegralInRange<int>(-100, 200),
              exception_state);
  cue.setAlign(V8AlignSetting(static_cast<V8AlignSetting::Enum>(
      choices.ConsumeIntegralInRange<unsigned>(0, V8AlignSetting::kEnumSize -
                                                      1))));
  cue.setVertical(V8DirectionSetting(static_cast<V8DirectionSetting::Enum>(
      choices.ConsumeIntegralInRange<unsigned>(
          0, V8DirectionSetting::kEnumSize - 1))));
  cue.setSnapToLines(choices.ConsumeBool());
  if (region && choices.ConsumeBool())
    cue.setRegion(region);

  cue.SetIsActive(true);
  cue.UpdateDisplay(container);

  cue.SetIsActive(false);
  cue.setSnapToLines(!cue.snapToLines());
  cue.setSize(choices.ConsumeIntegralInRange<int>(0, 100), exception_state);
  cue.SetIsActive(true);
  cue.UpdateDisplay(container);
}

}  // namespace

DEFINE_LLVM_FUZZER_TEST_ONE_INPUT_SPAN(
    const base::span<const uint8_t> data) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  test::TaskEnvironment task_environment;

  // WebVTTRegions is experimental and disabled by default. Toggle it here to
  // cover the region parser and display paths as well as default behavior.
  FuzzedDataProvider choices(data.data(), data.size());
  ScopedWebVTTRegionsForTest regions_enabled(choices.ConsumeBool());

  auto page_holder = std::make_unique<DummyPageHolder>(gfx::Size(640, 480));
  Document& document = page_holder->GetDocument();
  if (document.body())
    document.body()->RemoveChildren();
  HTMLDivElement* source_element =
      MakeGarbageCollected<HTMLDivElement>(document);
  auto* track = MakeGarbageCollected<TextTrack>(
      V8TextTrackKind(V8TextTrackKind::Enum::kSubtitles), g_empty_atom,
      g_empty_atom, *source_element);
  track->SetReadinessState(TextTrack::kLoaded);
  track->SetModeEnum(TextTrackMode::kShowing);

  auto* client = MakeGarbageCollected<FuzzerParserClient>();
  auto* parser = MakeGarbageCollected<VTTParser>(client, document);
  const base::span<const char> body = base::as_chars(data);

  size_t offset = 0;
  unsigned chunks = 0;
  while (offset < body.size()) {
    const size_t remaining = body.size() - offset;
    size_t chunk_size =
        choices.ConsumeIntegralInRange<size_t>(
            1, std::min(remaining, static_cast<size_t>(256)));
    if (remaining >= 3 && chunks < 3)
      chunk_size = chunks + 1;
    parser->ParseBytes(body.subspan(offset, chunk_size));
    offset += chunk_size;
    ++chunks;
  }
  // A failed header parse leaves buffered bytes pending, so Flush() would
  // violate the parser's end-of-stream assertion.
  if (!client->parse_failed())
    parser->Flush();

  HeapVector<Member<TextTrackCue>> cues;
  parser->GetNewCues(cues);
  HeapVector<Member<CSSStyleSheet>> style_sheets;
  parser->GetNewStyleSheets(style_sheets);

  HTMLDivElement* container = MakeGarbageCollected<HTMLDivElement>(document);
  if (document.body())
    document.body()->AppendChild(container);

  for (wtf_size_t i = 0; i < cues.size() && i < 64; ++i) {
    auto* cue = static_cast<VTTCue*>(cues[i].Get());

    track->addCue(cue);
    ExerciseCue(*cue, *container, cue->region(), choices);
    if (cue->region() && i < 16)
      ExerciseRegion(*cue->region(), document, choices);
  }
  document.UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  for (wtf_size_t i = 0; i < cues.size() && i < 64; ++i) {
    auto* cue = static_cast<VTTCue*>(cues[i].Get());
    cue->SetIsActive(false);
    track->removeCue(cue, ASSERT_NO_EXCEPTION);
  }
  if (container->parentNode())
    container->parentNode()->RemoveChild(container);
  page_holder.reset();
  static unsigned iteration;
  if ((++iteration % 16) == 0) {
    ThreadState::Current()->CollectAllGarbageForTesting(
        ThreadState::StackState::kNoHeapPointers);
  }

  return 0;
}

}  // namespace blink
