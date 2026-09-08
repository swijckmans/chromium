// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzes the clipboard/drag-and-drop markup sanitizer
// (CreateStrictlyProcessedMarkupWithContext). Untrusted markup reaches it from
// any paste or drop under default flags, and the sanitized string is handed to
// web content via navigator.clipboard.read() and to the editing paste path.
// Its contract is that the output contains no script, no plugin content and
// nothing Element::StripScriptingAttributes would strip; the harness re-parses
// the output with scripting *allowed* (as a consumer's innerHTML would) and
// CHECKs that contract, so a mutation-based bypass is reported even when no
// memory error occurs.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/no_destructor.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/parser_content_policy.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/svg/svg_uri_reference.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// Page setup dominates per-input cost, so the page is created once and reused.
class Environment {
 public:
  Environment() : page_holder_(std::make_unique<DummyPageHolder>()) {}

  LocalFrame& GetFrame() { return page_holder_->GetFrame(); }
  Document& GetDocument() { return page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

// Exercising a javascript: base URL matters because relative URLs in the
// output are resolved against it when ResolveUrls is requested.
const char* const kBaseUrls[] = {
    "",
    "http://example.com/dir/page.html",
    "javascript:alert(1)//",
    "data:text/html,x",
};

void CheckSubtreeIsSanitized(const Node& root);

void CheckElementIsSanitized(const Element& element) {
  CHECK(!element.IsScriptElement())
      << "script element survived sanitization: " << element.TagQName();
  CHECK(!IsA<HTMLPlugInElement>(element) &&
        !element.HasTagName(html_names::kAppletTag))
      << "plugin element survived sanitization: " << element.TagQName();

  for (const Attribute& attribute : element.Attributes()) {
    CHECK(!element.IsScriptingAttribute(attribute))
        << "scripting attribute survived sanitization: " << attribute.GetName()
        << "=\"" << attribute.Value() << "\" on " << element.TagQName();
  }

  if (auto* use = DynamicTo<SVGUseElement>(element)) {
    SVGURLReferenceResolver resolver(use->HrefString(), use->GetDocument());
    CHECK(resolver.IsLocal() && !resolver.AbsoluteUrl().ProtocolIsData())
        << "non-local <use> href survived sanitization: " << use->HrefString();
  }

  if (ShadowRoot* shadow_root = element.GetShadowRoot()) {
    CheckSubtreeIsSanitized(*shadow_root);
  }
  if (auto* template_element = DynamicTo<HTMLTemplateElement>(element)) {
    if (DocumentFragment* content = template_element->content()) {
      CheckSubtreeIsSanitized(*content);
    }
  }
}

void CheckSubtreeIsSanitized(const Node& root) {
  for (Node& node : NodeTraversal::DescendantsOf(root)) {
    if (auto* element = DynamicTo<Element>(node)) {
      CheckElementIsSanitized(*element);
    }
  }
}

int FuzzStrictlyProcessedMarkup(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  static base::NoDestructor<Environment> environment;

  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input =
      UNSAFE_BUFFERS(base::span(data, size));
  const uint8_t control = input[0];
  const String markup = String::FromUtf8WithLatin1Fallback(input.subspan(1u));

  ScriptState* script_state =
      ToScriptStateForMainWorld(&environment->GetFrame());
  ScriptState::Scope scope(script_state);
  Document& document = environment->GetDocument();

  const String base_url(kBaseUrls[control & 0x03]);
  const ChildrenOnly children_only =
      (control & 0x04) ? kChildrenOnly : kIncludeNode;
  ResolveUrls resolve_urls = ResolveUrls::kNone;
  switch ((control >> 3) & 0x03) {
    case 1:
      resolve_urls = ResolveUrls::kAll;
      break;
    case 2:
      resolve_urls = ResolveUrls::kNonLocal;
      break;
    default:
      break;
  }

  // The clipboard path passes a sub-range of the markup as the fragment and
  // the rest as surrounding context (the StartFragment/EndFragment markers of
  // CF_HTML); cover both the whole-string and a sub-range case.
  wtf_size_t fragment_start = 0;
  wtf_size_t fragment_end = markup.length();
  if ((control & 0x20) && markup.length() >= 4) {
    fragment_start = markup.length() / 4;
    fragment_end = markup.length() - markup.length() / 4;
  }

  const String sanitized = CreateStrictlyProcessedMarkupWithContext(
      document, markup, fragment_start, fragment_end, base_url, children_only,
      resolve_urls);
  if (sanitized.IsNull()) {
    return 0;
  }

  // Re-parse the sanitized string the way a consumer would (scripting allowed)
  // and require the sanitizer's contract to hold on the result.
  DocumentFragment* replay = CreateFragmentFromMarkup(
      document, sanitized, base_url, kAllowScriptingContent);
  if (replay) {
    CheckSubtreeIsSanitized(*replay);
  }

  if (control & 0x40) {
    DocumentFragment* fragment =
        CreateStrictlyProcessedFragmentFromMarkupWithContext(
            document, markup, fragment_start, fragment_end, base_url);
    if (fragment) {
      CheckSubtreeIsSanitized(*fragment);
    }
  }
  return 0;
}

}  // namespace

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size >= 2 && size <= 32768) {
    blink::FuzzStrictlyProcessedMarkup(data, size);
  }
  return 0;
}
