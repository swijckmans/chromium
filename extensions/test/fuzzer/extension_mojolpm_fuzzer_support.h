// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef EXTENSIONS_TEST_FUZZER_EXTENSION_MOJOLPM_FUZZER_SUPPORT_H_
#define EXTENSIONS_TEST_FUZZER_EXTENSION_MOJOLPM_FUZZER_SUPPORT_H_

#include <memory>

#include "base/files/scoped_temp_dir.h"
#include "base/memory/raw_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "content/public/common/child_process_id.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"

namespace content {
class BrowserContext;
class TestRenderFrameHost;
class TestWebContents;
}  // namespace content

class PrefService;
class ExtensionPrefValueMap;

namespace extensions {
class Extension;
class ExtensionWebContentsObserver;

namespace mojolpm {

inline constexpr char kExtensionIdA[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
inline constexpr char kExtensionIdB[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

class ExtensionsFuzzerEnvironment : public content::mojolpm::FuzzerEnvironment {
 public:
  ExtensionsFuzzerEnvironment();
  ~ExtensionsFuzzerEnvironment() override;

  ExtensionsFuzzerEnvironment(const ExtensionsFuzzerEnvironment&) = delete;
  ExtensionsFuzzerEnvironment& operator=(
      const ExtensionsFuzzerEnvironment&) = delete;

  void SetFuzzerContext(content::BrowserContext* context);
  void SetFuzzerObserver(extensions::ExtensionWebContentsObserver* observer);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

ExtensionsFuzzerEnvironment& GetEnvironment();
scoped_refptr<base::SequencedTaskRunner> GetFuzzerTaskRunner();

class ExtensionFuzzerWorld {
 public:
  explicit ExtensionFuzzerWorld(
      content::mojolpm::RenderViewHostTestHarnessAdapter* test_adapter);
  ~ExtensionFuzzerWorld();

  ExtensionFuzzerWorld(const ExtensionFuzzerWorld&) = delete;
  ExtensionFuzzerWorld& operator=(const ExtensionFuzzerWorld&) = delete;

  void SetUp();
  void TearDown();

  content::BrowserContext* browser_context() const { return browser_context_; }
  const extensions::Extension* extension_a() const;
  content::TestRenderFrameHost* main_rfh() const { return main_rfh_; }
  content::TestWebContents* web_contents() const { return web_contents_; }
  content::ChildProcessId render_process_id() const { return process_id_; }

 private:
  raw_ptr<content::mojolpm::RenderViewHostTestHarnessAdapter> test_adapter_;
  raw_ptr<content::BrowserContext> browser_context_ = nullptr;
  raw_ptr<content::TestRenderFrameHost> main_rfh_ = nullptr;
  raw_ptr<content::TestWebContents> web_contents_ = nullptr;
  content::ChildProcessId process_id_;
  base::ScopedTempDir extension_dir_;
  std::unique_ptr<ExtensionPrefValueMap> extension_pref_value_map_;
  std::unique_ptr<::PrefService> pref_service_;
};

}  // namespace mojolpm
}  // namespace extensions

#endif  // EXTENSIONS_TEST_FUZZER_EXTENSION_MOJOLPM_FUZZER_SUPPORT_H_
