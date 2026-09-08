// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/no_destructor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_set_html_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/sanitizer/sanitizer.h"
#include "third_party/blink/renderer/core/sanitizer/sanitizer_builtins.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_type_policy_factory.h"
#include "third_party/blink/renderer/core/xlink_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// Page setup dominates per-input cost, so the page is created once and reused;
// every input parses into a fresh child of a fresh context element.
class Environment {
 public:
  Environment() : page_holder_(std::make_unique<DummyPageHolder>()) {}

  LocalFrame& GetFrame() { return page_holder_->GetFrame(); }
  Document& GetDocument() { return page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

bool IsJavaScriptUrlAttribute(const Element& element,
                              const QualifiedName& attribute) {
  const AtomicString& value = element.getAttribute(attribute);
  return value && ProtocolIsJavaScript(value);
}

bool AnimatesHref(const Element& element) {
  const AtomicString& value =
      element.getAttribute(svg_names::kAttributeNameAttr);
  AtomicString prefix;
  AtomicString local_name;
  return Document::ParseQualifiedName(
             value, prefix, local_name, IGNORE_EXCEPTION,
             Document::QualifiedNameParsingMode::kParsingAttribute) &&
         local_name == html_names::kHrefAttr.LocalName();
}

// Everything the safe sanitizer is *always* required to remove, regardless of
// configuration: the baseline element/attribute lists, event handlers, and
// javascript: navigation URLs. Anything here surviving Element::setHTML is a
// sanitizer bypass.
void CheckElementIsSafe(const Element& element) {
  const Sanitizer* baseline = SanitizerBuiltins::GetBaseline();
  const QualifiedName& tag = element.TagQName();

  CHECK(!baseline->RemoveElements()->Contains(tag))
      << "baseline element survived: " << tag;

  for (const QualifiedName& name : element.getAttributeQualifiedNames()) {
    CHECK(!baseline->RemoveAttrs()->Contains(name))
        << "baseline attribute survived: " << name;
    CHECK(name.NamespaceURI() ||
          !TrustedTypePolicyFactory::IsEventHandlerAttributeName(
              name.LocalName()))
        << "event handler survived: " << name;
  }

  bool javascript_url = false;
  if (html_names::kATag.Matches(tag) || html_names::kAreaTag.Matches(tag) ||
      html_names::kBaseTag.Matches(tag)) {
    javascript_url = IsJavaScriptUrlAttribute(element, html_names::kHrefAttr);
  } else if (svg_names::kATag.Matches(tag) ||
             element.namespaceURI() == mathml_names::kNamespaceURI) {
    javascript_url = IsJavaScriptUrlAttribute(element, html_names::kHrefAttr) ||
                     IsJavaScriptUrlAttribute(element, xlink_names::kHrefAttr);
  } else if (html_names::kButtonTag.Matches(tag) ||
             html_names::kInputTag.Matches(tag)) {
    javascript_url =
        IsJavaScriptUrlAttribute(element, html_names::kFormactionAttr);
  } else if (html_names::kFormTag.Matches(tag)) {
    javascript_url = IsJavaScriptUrlAttribute(element, html_names::kActionAttr);
  } else if (svg_names::kAnimateTag.Matches(tag) ||
             svg_names::kAnimateTransformTag.Matches(tag) ||
             svg_names::kSetTag.Matches(tag)) {
    CHECK(!AnimatesHref(element)) << "SVG href animation survived";
  }
  CHECK(!javascript_url) << "javascript: navigation URL survived on " << tag;
}

void CheckSubtreeIsSafe(const Node& root);

void CheckNestedTreesAreSafe(Element& element) {
  if (ShadowRoot* shadow_root = element.GetShadowRoot()) {
    CheckSubtreeIsSafe(*shadow_root);
  }
  if (auto* template_element = DynamicTo<HTMLTemplateElement>(element)) {
    if (DocumentFragment* content = template_element->content()) {
      CheckSubtreeIsSafe(*content);
    }
  }
}

void CheckSubtreeIsSafe(const Node& root) {
  for (Node& node : NodeTraversal::DescendantsOf(root)) {
    auto* element = DynamicTo<Element>(node);
    if (!element) {
      continue;
    }
    CheckElementIsSafe(*element);
    CheckNestedTreesAreSafe(*element);
  }
}

int FuzzSanitizer(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  static base::NoDestructor<Environment> environment;

  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input =
      UNSAFE_BUFFERS(base::span(data, size));
  const uint8_t control = input[0];
  String markup = String::FromUtf8WithLatin1Fallback(input.subspan(1u));

  // The sanitizer reports errors as DOMExceptions, so a live script context
  // is required.
  ScriptState* script_state =
      ToScriptStateForMainWorld(&environment->GetFrame());
  ScriptState::Scope scope(script_state);

  // The streaming (parse-time) sanitizer is the default; the post-parse
  // fallback is still reachable if the feature is disabled, so keep covering
  // it.
  ScopedStreamingSanitizerForTest streaming((control & 0x03) != 0x03);

  Document& document = environment->GetDocument();
  const QualifiedName* context_tag = nullptr;
  switch ((control >> 2) & 0x07) {
    case 0:
      context_tag = &html_names::kDivTag;
      break;
    case 1:
      context_tag = &html_names::kTemplateTag;
      break;
    case 2:
      context_tag = &html_names::kTableTag;
      break;
    case 3:
      context_tag = &html_names::kSelectTag;
      break;
    case 4:
      context_tag = &html_names::kTitleTag;
      break;
    case 5:
      context_tag = &html_names::kStyleTag;
      break;
    case 6:
      context_tag = &html_names::kTextareaTag;
      break;
    default:
      context_tag = &html_names::kBodyTag;
      break;
  }
  Element* context = document.CreateRawElement(*context_tag);
  document.body()->AppendChild(context);

  {
    DummyExceptionStateForTesting exception;
    context->setHTML(markup, SetHTMLOptions::Create(), exception);
    if (!exception.HadException()) {
      CheckSubtreeIsSafe(*context);
      CheckNestedTreesAreSafe(*context);
    }
  }

  context->remove();
  return 0;
}

}  // namespace

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Control byte plus markup; cap length to avoid non-actionable timeouts.
  if (size >= 2 && size <= 32768) {
    blink::FuzzSanitizer(data, size);
  }
  return 0;
}
