// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "base/at_exit.h"
#include "base/check.h"
#include "base/command_line.h"
#include "base/i18n/icu_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/test/test_timeouts.h"
#include "base/time/time.h"
#include "pdf/accessibility.h"
#include "pdf/buildflags.h"
#include "pdf/pdf_features.h"
#include "pdf/loader/url_loader.h"
#include "pdf/pdfium/pdfium_engine.h"
#include "pdf/pdfium/pdfium_form_filler.h"
#include "pdf/pdfium/pdfium_page.h"
#include "pdf/test/test_client.h"
#include "pdf/test/test_document_loader.h"
#include "pdf/test/test_helpers.h"
#include "pdf/text_search.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "testing/libfuzzer/libfuzzer_exports.h"
#include "ui/events/keycodes/keyboard_codes.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/size.h"

namespace {

class FuzzerEnvironment {
 public:
  FuzzerEnvironment() {
    if (!base::CommandLine::InitializedForCurrentProcess()) {
      base::CommandLine::Init(0, nullptr);
    }
    CHECK(base::i18n::InitializeICU());
    TestTimeouts::Initialize();
    task_environment_ = std::make_unique<base::test::TaskEnvironment>(
        base::test::TaskEnvironment::MainThreadType::IO);
#if BUILDFLAG(ENABLE_PDF_INK2)
    pdf_ink_features_.InitAndEnableFeature(chrome_pdf::features::kPdfInk2);
#endif
    chrome_pdf::InitializeSDK(/*enable_v8=*/false, /*use_skia=*/false,
                              chrome_pdf::FontMappingMode::kNoMapping);
  }

  FuzzerEnvironment(const FuzzerEnvironment&) = delete;
  FuzzerEnvironment& operator=(const FuzzerEnvironment&) = delete;

  ~FuzzerEnvironment() { chrome_pdf::ShutdownSDK(); }

  void RunUntilIdle() { task_environment_->RunUntilIdle(); }

 private:
  base::AtExitManager at_exit_manager_;
  std::unique_ptr<base::test::TaskEnvironment> task_environment_;
#if BUILDFLAG(ENABLE_PDF_INK2)
  base::test::ScopedFeatureList pdf_ink_features_;
#endif
};

FuzzerEnvironment& GetFuzzerEnvironment() {
  static FuzzerEnvironment environment;
  return environment;
}

class FuzzerClient : public chrome_pdf::TestClient {
 public:
  FuzzerClient() : TestClient(/*use_skia_renderer=*/false) {}

  std::vector<SearchStringResult> SearchString(
      const std::u16string& needle,
      const std::u16string& haystack,
      bool case_sensitive) override {
    return chrome_pdf::TextSearch(needle, haystack, case_sensitive);
  }
};

void ExerciseAccessibility(chrome_pdf::PDFiumEngine* engine,
                           bool enable_pdf_tags) {
  base::test::ScopedFeatureList pdf_tags;
  // kPdfTags is disabled by default. Enable it for selected inputs to cover
  // raw text-run pointers and recursive tagged-PDF structure traversal.
  if (enable_pdf_tags) {
    pdf_tags.InitAndEnableFeature(chrome_pdf::features::kPdfTags);
  }

  const int page_count = std::min(engine->GetNumberOfPages(), 4);
  for (int page_index = 0; page_index < page_count; ++page_index) {
    chrome_pdf::PDFiumPage* page = engine->GetPage(page_index);
    if (!page) {
      continue;
    }

    page->PopulateTextRunTypeAndImageAltText();
    page->GetCharInfo();
    page->GetTextRunInfo();
    page->GetLinkInfo();
    page->GetImageInfo();
    page->GetHighlightInfo();
    page->GetTextFieldInfo();
    page->GetStructureTree();

    const int char_count = page->GetCharCount();
    if (char_count > 0) {
      page->GetCharUnicode(0);
      page->GetCharBounds(0);
      page->GetTextRunInfoAt(0);
    }

    int char_index = -1;
    chrome_pdf::PdfRect char_bounds;
    int form_type = 0;
    chrome_pdf::PDFiumPage::LinkTarget target;
    page->GetCharInfo(gfx::PointF(), &char_index, &char_bounds, &form_type,
                      &target);

    const auto links = page->GetLinkInfo();
    for (size_t link_index = 0; link_index < links.size(); ++link_index) {
      page->GetLinkTargetAtIndex(static_cast<int>(link_index), &target);
    }

    chrome_pdf::AccessibilityPageInfo page_info;
    std::vector<chrome_pdf::AccessibilityTextRunInfo> text_runs;
    std::vector<chrome_pdf::AccessibilityCharInfo> chars;
    chrome_pdf::AccessibilityPageObjects page_objects;
    chrome_pdf::GetAccessibilityInfo(engine, page_index, page_info, text_runs,
                                     chars, page_objects);
  }

  engine->GetStructureTree();
}

void ExerciseDocumentInfo(chrome_pdf::PDFiumEngine* engine,
                          FuzzedDataProvider& provider) {
  engine->GetBookmarks();
  engine->GetDocumentMetadata();

  const auto& attachments = engine->GetDocumentAttachmentInfoList();
  for (size_t i = 0; i < attachments.size(); ++i) {
    if (attachments[i].is_readable && attachments[i].size_bytes > 0 &&
        attachments[i].size_bytes <= 64 * 1024 &&
        provider.ConsumeBool()) {
      engine->GetAttachmentData(i);
    }
  }

  engine->GetNamedDestination(provider.ConsumeRandomLengthString(128));
  const int page_count = std::min(engine->GetNumberOfPages(), 4);
  for (int page_index = 0; page_index < page_count; ++page_index) {
    const gfx::Rect page_rect = engine->GetPageScreenRect(page_index);
    const gfx::PointF point(
        provider.ConsumeIntegralInRange<int>(page_rect.x() - 32,
                                             page_rect.right() + 32),
        provider.ConsumeIntegralInRange<int>(page_rect.y() - 32,
                                             page_rect.bottom() + 32));
    engine->GetLinkAtPosition(point);
  }
}

void ExerciseFormInput(chrome_pdf::PDFiumEngine* engine,
                       FuzzedDataProvider& provider) {
  static constexpr std::array<int, 10> kKeyCodes = {
      ui::VKEY_TAB,      ui::VKEY_RETURN, ui::VKEY_BACK,  ui::VKEY_LEFT,
      ui::VKEY_RIGHT,    ui::VKEY_UP,     ui::VKEY_DOWN,  ui::VKEY_HOME,
      ui::VKEY_END,      ui::VKEY_DELETE,
  };
  static constexpr std::array<blink::WebPointerProperties::Button, 4>
      kButtons = {
      blink::WebPointerProperties::Button::kNoButton,
      blink::WebPointerProperties::Button::kLeft,
      blink::WebPointerProperties::Button::kMiddle,
      blink::WebPointerProperties::Button::kRight,
  };
  static constexpr std::array<blink::WebInputEvent::Type, 3> kMouseTypes = {
      blink::WebInputEvent::Type::kMouseDown,
      blink::WebInputEvent::Type::kMouseMove,
      blink::WebInputEvent::Type::kMouseUp,
  };

  const size_t event_count = provider.ConsumeIntegralInRange<size_t>(1, 32);
  for (size_t i = 0; i < event_count; ++i) {
    const gfx::PointF point(
        provider.ConsumeIntegralInRange<int>(0, 799),
        provider.ConsumeIntegralInRange<int>(0, 599));
    const int modifiers =
        provider.ConsumeIntegralInRange<int>(0, 7) &
        (blink::WebInputEvent::Modifiers::kShiftKey |
         blink::WebInputEvent::Modifiers::kControlKey |
         blink::WebInputEvent::Modifiers::kAltKey);

    if (provider.ConsumeBool()) {
      const auto type = provider.ConsumeEnum<blink::WebInputEvent::Type>();
      const auto mouse_type =
          kMouseTypes.at(static_cast<size_t>(type) % kMouseTypes.size());
      blink::WebMouseEvent event(
          mouse_type, point, point,
          kButtons.at(provider.ConsumeIntegralInRange<size_t>(
              0, kButtons.size() - 1)),
          provider.ConsumeIntegralInRange<int>(1, 3), modifiers,
          blink::WebInputEvent::GetStaticTimeStampForTests());
      engine->HandleInputEvent(event);
    } else {
      blink::WebKeyboardEvent event(
          provider.ConsumeBool()
              ? blink::WebInputEvent::Type::kKeyDown
              : blink::WebInputEvent::Type::kRawKeyDown,
          modifiers, blink::WebInputEvent::GetStaticTimeStampForTests());
      event.windows_key_code =
          kKeyCodes.at(provider.ConsumeIntegralInRange<size_t>(
              0, kKeyCodes.size() - 1));
      engine->HandleInputEvent(event);
    }

    if (provider.ConsumeBool() && engine->CanEditText()) {
      engine->ReplaceSelection(provider.ConsumeRandomLengthString(64));
    }
    if (provider.ConsumeBool()) {
      engine->SelectAll();
    }
    engine->GetSelectedText();
  }
}

void ExerciseSelection(chrome_pdf::PDFiumEngine* engine) {
  engine->GetSelectedText();
  engine->GetSelectionRectMap();
}

#if BUILDFLAG(ENABLE_PDF_INK2)
void ExerciseInkAnnotations(chrome_pdf::PDFiumEngine* engine,
                            FuzzedDataProvider& provider) {
  engine->ScanForInkAnnotations(base::Milliseconds(100));
  engine->LoadTextAnnotationsFromPdf();
  const int page_count = std::min(engine->GetNumberOfPages(), 4);
  for (int i = 0; i < page_count; ++i) {
    engine->LoadV2InkPathsForPage(i);
  }
}
#endif

void ExercisePrintAndSave(chrome_pdf::PDFiumEngine* engine,
                          FuzzedDataProvider& provider) {
  const int page_count = std::min(engine->GetNumberOfPages(), 2);
  if (page_count <= 0) {
    return;
  }
  std::vector<int> page_indices;
  for (int i = 0; i < page_count; ++i) {
    page_indices.push_back(i);
  }

  blink::WebPrintParams print_params = chrome_pdf::GetDefaultPrintParams();
  print_params.rasterize_pdf = provider.ConsumeBool();

  engine->PrintBegin();
  engine->PrintPages(page_indices, print_params);
  engine->PrintEnd();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > 65536) {
    return 0;
  }

  FuzzerEnvironment& environment = GetFuzzerEnvironment();
  FuzzedDataProvider provider(data, size);

  const size_t fragment_count =
      provider.ConsumeIntegralInRange<size_t>(1, 4);
  std::vector<std::string> text_fragments;
  text_fragments.reserve(fragment_count);
  for (size_t i = 0; i < fragment_count; ++i) {
    text_fragments.push_back(provider.ConsumeRandomLengthString(200));
  }

  std::u16string find_term =
      base::UTF8ToUTF16(provider.ConsumeRandomLengthString(200));
  const bool case_sensitive = provider.ConsumeBool();
  std::vector<uint8_t> pdf_data = provider.ConsumeRemainingBytes<uint8_t>();
  if (pdf_data.empty()) {
    return 0;
  }
  FuzzedDataProvider action_provider(pdf_data.data(), pdf_data.size());
  const bool enable_pdf_tags = action_provider.ConsumeBool();

  FuzzerClient client;
  auto engine = std::make_unique<chrome_pdf::PDFiumEngine>(
      &client, chrome_pdf::PDFiumFormFiller::ScriptOption::kNoJavaScript);
  auto loader = std::make_unique<chrome_pdf::TestDocumentLoader>(
      engine.get(), std::move(pdf_data));
  chrome_pdf::TestDocumentLoader* loader_ptr = loader.get();
  client.set_engine(engine.get());
  engine->SetDocumentLoaderForTesting(std::move(loader));
  if (!engine->HandleDocumentLoad(nullptr, "https://example.test/test.pdf")) {
    client.set_engine(nullptr);
    return 0;
  }

  engine->PluginSizeUpdated(gfx::Size(800, 600));
  while (loader_ptr->SimulateLoadData(1024)) {
  }
  environment.RunUntilIdle();
  if (engine->GetNumberOfPages() == 0) {
    client.set_engine(nullptr);
    return 0;
  }

  if (engine->FindAndHighlightTextFragments(text_fragments)) {
    engine->ScrollTextFragmentIntoView();
  }

  if (!find_term.empty()) {
    engine->StartFind(find_term, case_sensitive);
    engine->SelectFindResult(/*forward=*/true);
    ExerciseSelection(engine.get());
    engine->SelectFindResult(/*forward=*/false);
    ExerciseSelection(engine.get());
  }
  engine->SelectAll();
  ExerciseSelection(engine.get());
  ExerciseAccessibility(engine.get(), enable_pdf_tags);
  ExerciseDocumentInfo(engine.get(), action_provider);
  ExerciseFormInput(engine.get(), action_provider);
#if BUILDFLAG(ENABLE_PDF_INK2)
  if (action_provider.ConsumeBool()) {
    ExerciseInkAnnotations(engine.get(), action_provider);
  }
#endif
  if (action_provider.ConsumeBool()) {
    ExercisePrintAndSave(engine.get(), action_provider);
  }
  if (action_provider.ConsumeBool()) {
    engine->GetSaveData();
  }
  environment.RunUntilIdle();

  client.set_engine(nullptr);
  return 0;
}
