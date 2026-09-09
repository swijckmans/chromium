// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzes Blink's script-reachable editing commands. There is no in-tree
// fuzzer covering this editing command layer.

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <memory>

#include "base/containers/span.h"
#include "base/no_destructor.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/commands/editor_command.h"
#include "third_party/blink/renderer/core/editing/commands/editor_command_names.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/blink_fuzzer_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Environment {
 public:
  Environment() : page_holder_(std::make_unique<DummyPageHolder>()) {}

  LocalFrame& GetFrame() { return page_holder_->GetFrame(); }
  Document& GetDocument() { return page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

namespace {

#define BLINK_EDITING_COMMAND_NAME(name) #name,
static constexpr auto kCommandNames = std::to_array<const char*>(
    {FOR_EACH_BLINK_EDITING_COMMAND_NAME(BLINK_EDITING_COMMAND_NAME)});
#undef BLINK_EDITING_COMMAND_NAME

}  // namespace

int FuzzEditingExecCommand(const uint8_t* data, size_t size) {
  static BlinkFuzzerTestSupport test_support = BlinkFuzzerTestSupport();
  static base::NoDestructor<Environment> environment;

  // SAFETY: libFuzzer guarantees `data` points to `size` valid bytes.
  const base::span<const uint8_t> input =
      UNSAFE_BUFFERS(base::span(data, size));
  const uint16_t requested_html_length =
      static_cast<uint16_t>(input[0]) | (static_cast<uint16_t>(input[1]) << 8);
  const uint8_t flags = input[2];
  const size_t available_length = input.size() - 4;
  const size_t html_length =
      std::min<size_t>(requested_html_length, available_length);
  const String initial_html =
      String::FromUtf8(input.subspan(size_t{4}, html_length));

  LocalFrame& frame = environment->GetFrame();
  Document& document = environment->GetDocument();
  HTMLElement* body = document.body();
  if (!body) {
    return 0;
  }

  body->SetInnerHTMLWithoutTrustedTypes(g_empty_string);
  frame.GetEditor().Clear();
  frame.Selection().Clear();
  document.setDesignMode("off");
  body->removeAttribute(html_names::kContenteditableAttr);

  DummyExceptionStateForTesting exception_state;
  if (flags & 0x01) {
    body->setContentEditable("true", exception_state);
  } else {
    document.setDesignMode("on");
  }
  body->SetInnerHTMLWithoutTrustedTypes(initial_html, exception_state);
  document.UpdateStyleAndLayoutTree();

  SelectionInDomTree selection =
      (flags & 0x02)
          ? SelectionInDomTree::Builder().Collapse(Position(*body, 0)).Build()
          : SelectionInDomTree::Builder().SelectAllChildren(*body).Build();
  frame.Selection().SetSelection(selection, SetSelectionOptions());

  document.UpdateStyleAndLayoutTree();
  frame.GetEditor()
      .CreateCommand(AtomicString("StyleWithCss"), EditorCommandSource::kDom)
      .Execute((flags & 0x04) ? "true" : "false");

  size_t offset = size_t{4} + html_length;
  for (size_t command_count = 0; command_count < 32 && offset < input.size();
       ++command_count) {
    const uint8_t command_index = input[offset++];
    if (offset == input.size()) {
      break;
    }
    const size_t requested_value_length = input[offset++];
    if (requested_value_length > input.size() - offset) {
      break;
    }
    const size_t value_length = requested_value_length;
    const String value = String::FromUtf8(input.subspan(offset, value_length));
    offset += value_length;

    document.UpdateStyleAndLayoutTree();
    frame.GetEditor()
        .CreateCommand(
            AtomicString(kCommandNames[command_index % kCommandNames.size()]),
            EditorCommandSource::kDom)
        .Execute(value);
  }

  return 0;
}

}  // namespace blink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size >= 4 && size <= 65536) {
    blink::FuzzEditingExecCommand(data, size);
  }
  return 0;
}
