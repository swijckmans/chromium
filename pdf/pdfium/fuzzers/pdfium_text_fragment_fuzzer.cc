// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <algorithm>
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
#include "base/test/task_environment.h"
#include "base/test/test_timeouts.h"
#include "pdf/loader/url_loader.h"
#include "pdf/pdfium/pdfium_engine.h"
#include "pdf/pdfium/pdfium_form_filler.h"
#include "pdf/pdfium/pdfium_page.h"
#include "pdf/test/test_client.h"
#include "pdf/test/test_document_loader.h"
#include "pdf/text_search.h"
#include "testing/libfuzzer/libfuzzer_exports.h"
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

void ExerciseAccessibility(chrome_pdf::PDFiumEngine* engine) {
  const int page_count = std::min(engine->GetNumberOfPages(), 3);
  for (int page_index = 0; page_index < page_count; ++page_index) {
    chrome_pdf::PDFiumPage* page = engine->GetPage(page_index);
    if (!page) {
      continue;
    }

    page->GetCharInfo();
    page->GetTextRunInfo();
    page->GetLinkInfo();
    page->GetHighlightInfo();
    page->GetTextFieldInfo();

    const int char_count = page->GetCharCount();
    if (char_count <= 0) {
      continue;
    }
    page->GetCharUnicode(0);
    page->GetCharBounds(0);
    page->GetTextRunInfoAt(0);

    int char_index = -1;
    chrome_pdf::PdfRect char_bounds;
    int form_type = 0;
    chrome_pdf::PDFiumPage::LinkTarget target;
    page->GetCharInfo(gfx::PointF(), &char_index, &char_bounds, &form_type,
                      &target);
  }
}

void ExerciseSelection(chrome_pdf::PDFiumEngine* engine) {
  engine->GetSelectedText();
  engine->GetSelectionRectMap();
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
  ExerciseAccessibility(engine.get());
  environment.RunUntilIdle();

  client.set_engine(nullptr);
  return 0;
}
