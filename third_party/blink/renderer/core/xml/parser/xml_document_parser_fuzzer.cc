// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzes Blink's XMLDocumentParser, which is attacker-reachable via DOMParser,
// XMLHttpRequest.responseXML, XSLT, and Element/DocumentFragment XML fragment
// parsing. The existing in-tree XML fuzzers drive libxml, expat and PDFium's
// XML reader directly; none of them exercise this Blink wrapper layer, which
// owns namespace/prefix resolution, parse-error synthesis and DOM
// construction.

#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/containers/span.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_supported_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/xml/dom_parser.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

int FuzzXMLParser(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  test::TaskEnvironment task_environment;

  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input =
      UNSAFE_BUFFERS(base::span(data, size));
  const uint8_t control = input[0];
  String source = String::FromUtf8WithLatin1Fallback(input.subspan(1u));

  // A real window and script context are needed: the parser reports
  // well-formedness and namespace errors as DOMExceptions.
  auto page_holder = std::make_unique<DummyPageHolder>();
  ScriptState* script_state =
      ToScriptStateForMainWorld(&page_holder->GetFrame());
  ScriptState::Scope scope(script_state);

  if (control & 0x01) {
    // Whole-document path, exactly as reached from script via DOMParser.
    V8SupportedType::Enum type;
    switch ((control >> 1) & 0x03) {
      case 0:
        type = V8SupportedType::Enum::kTextXml;
        break;
      case 1:
        type = V8SupportedType::Enum::kApplicationXhtmlXml;
        break;
      case 2:
        type = V8SupportedType::Enum::kImageSvgXml;
        break;
      default:
        type = V8SupportedType::Enum::kApplicationXml;
        break;
    }
    DOMParser::Create(script_state)
        ->ParseFromStringWithoutTrustedTypes(source, V8SupportedType(type));
  } else {
    // Fragment path (innerHTML on XML documents): the context element's
    // namespace drives prefix resolution, so alternate XHTML and SVG.
    Document& document = page_holder->GetDocument();
    DummyExceptionStateForTesting exception;
    Element* context = document.createElementNS(
        (control & 0x02) ? svg_names::kNamespaceURI
                         : html_names::xhtmlNamespaceURI,
        AtomicString((control & 0x02) ? "svg" : "div"), exception);
    if (!context || exception.HadException()) {
      return 0;
    }
    DocumentFragment* fragment = DocumentFragment::Create(document);
    DummyExceptionStateForTesting parse_exception;
    fragment->ParseXML(source, context, parse_exception);
  }
  return 0;
}

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Control byte plus markup; cap length to avoid non-actionable timeouts.
  if (size >= 2 && size <= 32768) {
    blink::FuzzXMLParser(data, size);
  }
  return 0;
}
