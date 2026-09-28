// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzes speculation rules parsing (<script type=speculationrules> and the
// Speculation-Rules header) together with document-rule matching against a
// document that contains links. Nothing in-tree fuzzes this layer.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/containers/span.h"
#include "base/no_destructor.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rule_set.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

constexpr char kDocumentUrl[] = "https://example.test/dir/page.html?q=1";

// A fixed link population so document rules ("where" clauses with href and
// selector predicates, eagerness, requires, etc.) have something to match.
constexpr char kBodyHtml[] = R"HTML(
  <a id=a1 class="c1 nav" href="/dir/one.html">one</a>
  <a id=a2 class="c2" href="https://example.test/two?x=1#f" rel=noreferrer>two</a>
  <a id=a3 class="c1 ext" href="https://other.test/three" target=_blank>three</a>
  <a id=a4 href="//other.test:8443/four" referrerpolicy=no-referrer>four</a>
  <area id=a5 href="../five" alt=five>
  <a id=a6 href="javascript:void(0)">six</a>
  <a id=a7 href="mailto:x@example.test">seven</a>
  <a id=a8 href="data:text/html,x">eight</a>
  <a id=a9>nine</a>
  <a id=a10 href="">ten</a>
  <div hidden><a id=a11 class=c2 href="/hidden">eleven</a></div>
  <a id=a12 href="https://example.test/twelve" data-x="1">twelve</a>
)HTML";

}  // namespace

class Environment {
 public:
  Environment()
      : page_holder_(std::make_unique<DummyPageHolder>(gfx::Size(800, 600))) {
    Document& document = GetDocument();
    document.SetURL(KURL(kDocumentUrl));
    document.SetBaseURLOverride(KURL(kDocumentUrl));
    document.body()->SetInnerHTMLWithoutTrustedTypes(kBodyHtml);
    document.View()->UpdateAllLifecyclePhasesForTest();
  }

  Document& GetDocument() { return page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

int FuzzSpeculationRuleSet(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  static base::NoDestructor<Environment> environment;

  if (size < 1) {
    return 0;
  }

  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input =
      UNSAFE_BUFFERS(base::span(data, size));
  const uint8_t flags = input[0];
  const String source_text = String::FromUtf8(input.subspan(size_t{1}));

  Document& document = environment->GetDocument();
  SpeculationRuleSet::Source* source = nullptr;
  switch (flags & 0x3) {
    case 0:
      source = SpeculationRuleSet::Source::FromInlineScript(
          source_text, document, document.body()->GetDomNodeId());
      break;
    case 1:
      source = SpeculationRuleSet::Source::FromRequest(
          source_text, KURL("https://rules.example.test/r/rules.json"),
          /*request_id=*/1);
      break;
    case 2:
      source = SpeculationRuleSet::Source::FromRequest(
          source_text, KURL("https://example.test/dir/rules.json"),
          /*request_id=*/2);
      break;
    default:
      source = SpeculationRuleSet::Source::FromBrowserInjected(
          source_text, KURL(kDocumentUrl),
          BrowserInjectedSpeculationRuleOptOut::kRespect);
      break;
  }

  SpeculationRuleSet* rule_set =
      SpeculationRuleSet::Parse(source, document.GetExecutionContext());
  CHECK(rule_set);

  // Run the candidate pipeline (selector matching, document-rule predicate
  // evaluation, URL resolution, Mojo struct construction) synchronously.
  DocumentSpeculationRules& rules = DocumentSpeculationRules::From(document);
  rules.AddRuleSet(rule_set);
  if (flags & 0x4) {
    document.View()->UpdateAllLifecyclePhasesForTest();
  }
  rules.QueueUpdateSpeculationCandidates(/*force_style_update=*/true);
  test::RunPendingTasks();
  rules.RemoveRuleSet(rule_set);
  test::RunPendingTasks();

  return 0;
}

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  return blink::FuzzSpeculationRuleSet(data, size);
}
