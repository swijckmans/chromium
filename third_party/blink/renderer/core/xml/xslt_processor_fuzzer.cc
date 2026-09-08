// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzes Blink's script-reachable XSLTProcessor and its libxslt integration.
// There is no in-tree fuzzer covering this XSLT surface. DocLoaderFunc's
// synchronous fetches for document() and xsl:import fail in a DummyPageHolder,
// so remote-document loading is out of scope for this harness.

#include "third_party/blink/renderer/core/xml/xslt_processor.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <memory>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/no_destructor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_supported_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/xml/dom_parser.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Environment {
 public:
  Environment() : page_holder_(std::make_unique<DummyPageHolder>()) {
    CHECK(XSLTProcessor::IsXSLTEnabled(
        page_holder_->GetDocument().GetExecutionContext()));
  }

  LocalFrame& GetFrame() { return page_holder_->GetFrame(); }
  Document& GetDocument() { return page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

namespace {

V8SupportedType::Enum SourceType(uint8_t control) {
  switch (control & 0x03) {
    case 0:
      return V8SupportedType::Enum::kTextXml;
    case 1:
      return V8SupportedType::Enum::kApplicationXhtmlXml;
    case 2:
      return V8SupportedType::Enum::kImageSvgXml;
    default:
      return V8SupportedType::Enum::kApplicationXml;
  }
}

}  // namespace

int FuzzXSLTProcessor(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  static base::NoDestructor<Environment> environment;

  // Header byte 0: source type [1:0], transform [3:2], element import [4],
  // setParameter [5], HTML output [6], parameter namespace [7].
  // Header byte 1: parameter name [1:0]. Bytes 2-3 hold stylesheet length.
  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input =
      UNSAFE_BUFFERS(base::span(data, size));
  const uint8_t control = input[0];
  const uint8_t parameter_control = input[1];
  const uint16_t requested_stylesheet_length =
      static_cast<uint16_t>(input[2]) | (static_cast<uint16_t>(input[3]) << 8);
  const size_t markup_length = input.size() - 4;
  const size_t stylesheet_length = requested_stylesheet_length < markup_length
                                       ? requested_stylesheet_length
                                       : markup_length;
  const String stylesheet = String::FromUtf8WithLatin1Fallback(
      input.subspan(size_t{4}, stylesheet_length));
  const String source = String::FromUtf8WithLatin1Fallback(
      input.subspan(size_t{4} + stylesheet_length));

  ScriptState* script_state =
      ToScriptStateForMainWorld(&environment->GetFrame());
  ScriptState::Scope scope(script_state);
  DOMParser* parser = DOMParser::Create(script_state);
  Document* stylesheet_document = parser->ParseFromStringWithoutTrustedTypes(
      stylesheet, V8SupportedType(V8SupportedType::Enum::kTextXml));
  Document* source_document = parser->ParseFromStringWithoutTrustedTypes(
      source, V8SupportedType(SourceType(control)));
  if (!stylesheet_document || !source_document) {
    return 0;
  }

  DummyExceptionStateForTesting exception;
  XSLTProcessor* processor =
      XSLTProcessor::Create(environment->GetDocument(), exception);
  if (!processor || exception.HadException()) {
    return 0;
  }

  if (control & 0x10) {
    processor->importStylesheet(stylesheet_document);
  } else {
    Element* root = stylesheet_document->documentElement();
    if (!root) {
      return 0;
    }
    processor->importStylesheet(root);
  }

  if (control & 0x20) {
    static constexpr std::array<const char*, 3> kParameterNames = {"p", "param",
                                                                   "a:b"};
    const char* local_name =
        kParameterNames[std::min<size_t>(parameter_control & 0x03, 2)];
    const String parameter_value = stylesheet.length() > 256
                                       ? stylesheet.DeprecatedSubstring(0, 256)
                                       : stylesheet;
    processor->setParameter((control & 0x80) ? "http://example.com/ns" : "",
                            local_name, parameter_value);
  }

  switch ((control >> 2) & 0x03) {
    case 0:
      processor->transformToFragment(source_document,
                                     &environment->GetDocument());
      break;
    case 1:
      processor->transformToDocument(source_document);
      break;
    case 2: {
      String mime_type = (control & 0x40) ? "text/html" : "text/xml";
      String result;
      String encoding;
      processor->TransformToString(source_document, mime_type, result,
                                   encoding);
      break;
    }
    case 3:
      if (Element* root = source_document->documentElement()) {
        processor->transformToFragment(root, &environment->GetDocument());
      } else {
        processor->transformToFragment(source_document,
                                       &environment->GetDocument());
      }
      break;
  }
  return 0;
}

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size >= 5 && size <= 65536) {
    blink::FuzzXSLTProcessor(data, size);
  }
  return 0;
}
