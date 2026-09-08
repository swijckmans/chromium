// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzes the innerHTML fast-path parser (html_document_parser_fastpath.cc),
// which is attacker-reachable from any element.innerHTML / setHTMLUnsafe and
// is not covered by the existing tokenizer/preload-scanner fuzzers.

#include "third_party/blink/renderer/core/html/parser/html_document_parser_fastpath.h"

#include <stddef.h>
#include <stdint.h>

#include "base/containers/span.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

int FuzzFastPath(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  test::TaskEnvironment task_environment;

  // Control byte selects the context element and parsing behavior so the
  // fuzzer explores the different context-tag code paths of the fast path.
  // The remaining bytes are the markup.
  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input = UNSAFE_BUFFERS(base::span(data, size));
  const uint8_t control = input[0];

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());

  Element* context = nullptr;
  switch (control & 0x03) {
    case 0:
      context = MakeGarbageCollected<HTMLDivElement>(*document);
      break;
    case 1:
      context = MakeGarbageCollected<HTMLSpanElement>(*document);
      break;
    default:
      context = MakeGarbageCollected<HTMLTemplateElement>(*document);
      break;
  }

  HTMLFragmentParsingBehaviorSet behavior;
  if (control & 0x04) {
    behavior.Put(HTMLFragmentParsingBehavior::kStripInitialWhitespaceForBody);
  }
  if (control & 0x08) {
    behavior.Put(HTMLFragmentParsingBehavior::kIncludeShadowRoots);
  }
  ParserContentPolicy policy =
      (control & 0x10) ? ParserContentPolicy::kAllowScriptingContent
                       : ParserContentPolicy::kDisallowScriptingAndPluginContent;

  String source = String::FromUtf8WithLatin1Fallback(input.subspan(1u));

  DocumentFragment* fragment = DocumentFragment::Create(*document);
  bool failed_unsupported_tag = false;
  TryParsingHTMLFragment(source, *document, *fragment, *context, policy,
                         behavior, &failed_unsupported_tag);
  return 0;
}

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Need the control byte plus some markup; cap length to avoid non-actionable
  // timeouts on huge inputs.
  if (size >= 2 && size <= 32768) {
    blink::FuzzFastPath(data, size);
  }
  return 0;
}
