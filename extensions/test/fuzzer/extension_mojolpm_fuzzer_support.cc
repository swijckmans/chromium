// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "extensions/test/fuzzer/extension_mojolpm_fuzzer_support.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "components/prefs/pref_service.h"
#include "components/prefs/pref_service_factory.h"
#include "components/prefs/testing_pref_store.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/child_process_security_policy.h"
#include "content/common/url_schemes.h"
#include "content/public/common/content_client.h"
#include "content/public/test/test_content_client.h"
#include "content/test/test_render_frame_host.h"
#include "content/test/test_web_contents.h"
#include "extensions/browser/api/alarms/alarm_manager.h"
#include "extensions/browser/api/core_extensions_browser_api_provider.h"
#include "extensions/browser/api/extensions_api_client.h"
#include "extensions/browser/core_browser_context_keyed_service_factories.h"
#include "extensions/browser/event_router.h"
#include "extensions/browser/event_router_factory.h"
#include "extensions/browser/extension_function_registry.h"
#include "extensions/browser/extension_pref_value_map.h"
#include "extensions/browser/extension_prefs.h"
#include "extensions/browser/extension_prefs_factory.h"
#include "extensions/browser/extension_registry.h"
#include "extensions/browser/extension_web_contents_observer.h"
#include "extensions/browser/mock_extension_system.h"
#include "extensions/browser/permissions_manager.h"
#include "extensions/browser/process_map.h"
#include "extensions/browser/process_map_factory.h"
#include "extensions/browser/quota_service.h"
#include "extensions/browser/renderer_startup_helper.h"
#include "extensions/browser/test_extensions_browser_client.h"
#include "extensions/common/constants.h"
#include "extensions/common/extension.h"
#include "extensions/common/extension_builder.h"
#include "extensions/common/extensions_client.h"
#include "extensions/test/test_extensions_client.h"
#include "url/gurl.h"

namespace extensions::mojolpm {

namespace {

constexpr const char* kCmdline[] = {"extension_mojolpm_fuzzer", nullptr};

class FuzzerContentClient : public content::TestContentClient {
 public:
  void AddAdditionalSchemes(Schemes* schemes) override {
        schemes->standard_schemes.push_back(extensions::kExtensionScheme);
        schemes->savable_schemes.push_back(extensions::kExtensionScheme);
        schemes->service_worker_schemes.push_back(extensions::kExtensionScheme);
  }
};

class FuzzerExtensionsBrowserClient
    : public extensions::TestExtensionsBrowserClient {
 public:
  FuzzerExtensionsBrowserClient() {
    AddAPIProvider(
        std::make_unique<extensions::CoreExtensionsBrowserAPIProvider>());
  }

  void SetFuzzerContext(content::BrowserContext* context) {
    context_ = context;
  }

  void SetFuzzerObserver(
      extensions::ExtensionWebContentsObserver* observer) {
    observer_ = observer;
  }

  bool IsValidContext(void* context) override { return context == context_; }

  bool IsSameContext(content::BrowserContext* first,
                     content::BrowserContext* second) override {
    return first == second;
  }

  bool HasOffTheRecordContext(content::BrowserContext* context) override {
    return false;
  }

  content::BrowserContext* GetOffTheRecordContext(
      content::BrowserContext* context) override {
    return nullptr;
  }

  content::BrowserContext* GetOriginalContext(
      content::BrowserContext* context) override {
    return context;
  }

  content::BrowserContext* GetContextRedirectedToOriginal(
      content::BrowserContext* context) override {
    return context;
  }

  content::BrowserContext* GetContextRedirectedToOriginalWithoutAshInternals(
      content::BrowserContext* context) override {
    return context;
  }

  content::BrowserContext* GetContextOwnInstance(
      content::BrowserContext* context) override {
    return context;
  }

  content::BrowserContext* GetContextForOriginalOnly(
      content::BrowserContext* context) override {
    return context;
  }

  extensions::ExtensionWebContentsObserver* GetExtensionWebContentsObserver(
      content::WebContents* web_contents) override {
    return observer_;
  }

 private:
  raw_ptr<content::BrowserContext> context_ = nullptr;
  raw_ptr<extensions::ExtensionWebContentsObserver> observer_ = nullptr;
};

class FuzzerMockExtensionSystem : public extensions::MockExtensionSystem {
 public:
  explicit FuzzerMockExtensionSystem(content::BrowserContext* context)
      : MockExtensionSystem(context),
        quota_service_(std::make_unique<extensions::QuotaService>()) {}

  extensions::QuotaService* quota_service() override {
    return quota_service_.get();
  }

 private:
  std::unique_ptr<extensions::QuotaService> quota_service_;
};

}  // namespace

class ExtensionsFuzzerEnvironment::Impl {
 public:
  raw_ptr<content::ContentClient> previous_content_client =
      content::GetContentClientForTesting();
  raw_ptr<content::ContentBrowserClient> previous_browser_client =
      previous_content_client ? previous_content_client->browser() : nullptr;
  FuzzerContentClient content_client;
  extensions::TestExtensionsClient extensions_client;
  extensions::ExtensionsAPIClient extensions_api_client;
  FuzzerExtensionsBrowserClient browser_client;
  extensions::MockExtensionSystemFactory<FuzzerMockExtensionSystem>
      extension_system_factory;
  url::ScopedSchemeRegistryForTests scheme_registry;
};

ExtensionsFuzzerEnvironment::ExtensionsFuzzerEnvironment()
    : content::mojolpm::FuzzerEnvironment(1, kCmdline),
      impl_(std::make_unique<Impl>()) {
  content::SetContentClient(&impl_->content_client);
  content::SetBrowserClientForTesting(impl_->previous_browser_client);
  content::ReRegisterContentSchemesForTests();
  extensions::ExtensionsClient::Set(&impl_->extensions_client);
  impl_->browser_client.set_extension_system_factory(
      &impl_->extension_system_factory);
  extensions::ExtensionsBrowserClient::Set(&impl_->browser_client);
  ExtensionFunctionRegistry::GetInstance();
}

ExtensionsFuzzerEnvironment::~ExtensionsFuzzerEnvironment() {
  extensions::ExtensionsBrowserClient::Set(nullptr);
  extensions::ExtensionsClient::Set(nullptr);
  content::SetContentClient(impl_->previous_content_client);
  content::SetBrowserClientForTesting(impl_->previous_browser_client);
}

void ExtensionsFuzzerEnvironment::SetFuzzerContext(
    content::BrowserContext* context) {
  impl_->browser_client.SetFuzzerContext(context);
}

void ExtensionsFuzzerEnvironment::SetFuzzerObserver(
    extensions::ExtensionWebContentsObserver* observer) {
  impl_->browser_client.SetFuzzerObserver(observer);
}

ExtensionsFuzzerEnvironment& GetEnvironment() {
  static base::NoDestructor<ExtensionsFuzzerEnvironment> environment;
  return *environment;
}

scoped_refptr<base::SequencedTaskRunner> GetFuzzerTaskRunner() {
  return GetEnvironment().fuzzer_task_runner();
}

ExtensionFuzzerWorld::ExtensionFuzzerWorld(
    content::mojolpm::RenderViewHostTestHarnessAdapter* test_adapter)
    : test_adapter_(test_adapter) {}

ExtensionFuzzerWorld::~ExtensionFuzzerWorld() = default;

void ExtensionFuzzerWorld::SetUp() {
  browser_context_ = test_adapter_->browser_context();
  CHECK(extension_dir_.CreateUniqueTempDir());
  CHECK(base::WriteFile(extension_dir_.GetPath().AppendASCII("sw.js"),
                        "self.addEventListener('install', () => {});"));
  GetEnvironment().SetFuzzerContext(browser_context_);
  extensions::EnsureCoreBrowserContextKeyedServiceFactoriesBuilt();
  extensions::ProcessMapFactory::GetInstance();
  extensions::AlarmManager::GetFactoryInstance();
  BrowserContextDependencyManager::GetInstance()->MarkBrowserContextLive(
      browser_context_);

  extension_pref_value_map_ = std::make_unique<ExtensionPrefValueMap>();
  PrefServiceFactory pref_service_factory;
  pref_service_factory.set_user_prefs(new TestingPrefStore());
  pref_service_factory.set_extension_prefs(new TestingPrefStore());
  auto* pref_registry = new user_prefs::PrefRegistrySyncable();
  extensions::ExtensionPrefs::RegisterProfilePrefs(pref_registry);
  extensions::PermissionsManager::RegisterProfilePrefs(pref_registry);
  pref_service_ = pref_service_factory.Create(pref_registry);
  extensions::ExtensionPrefsFactory::GetInstance()->SetInstanceForTesting(
      browser_context_,
      extensions::ExtensionPrefs::Create(
          browser_context_, pref_service_.get(),
          browser_context_->GetPath().AppendASCII("Extensions"),
          extension_pref_value_map_.get(), false /* extensions_disabled */,
          std::vector<extensions::EarlyExtensionPrefsObserver*>()));
  extensions::EventRouterFactory::GetInstance()->SetTestingFactoryAndUse(
      browser_context_,
      base::BindOnce([](content::BrowserContext* context)
                         -> std::unique_ptr<KeyedService> {
        return std::make_unique<extensions::EventRouter>(
            context, extensions::ExtensionPrefs::Get(context));
      }));

  BrowserContextDependencyManager::GetInstance()
      ->CreateBrowserContextServicesForTest(browser_context_);

  auto extension_a =
      extensions::ExtensionBuilder("Extension A")
          .SetID(kExtensionIdA)
          .SetManifestVersion(3)
          .SetBackgroundContext(
              extensions::ExtensionBuilder::BackgroundContext::SERVICE_WORKER)
          .SetManifestKey("background.service_worker", "/sw.js")
          .SetPath(extension_dir_.GetPath())
          .AddAPIPermissions({"storage", "alarms"})
          .Build();
  auto extension_b =
      extensions::ExtensionBuilder("Extension B")
          .SetID(kExtensionIdB)
          .SetManifestVersion(3)
          .SetBackgroundContext(
              extensions::ExtensionBuilder::BackgroundContext::SERVICE_WORKER)
          .SetManifestKey("background.service_worker", "/sw.js")
          .SetPath(extension_dir_.GetPath())
          .AddAPIPermissions({"storage", "alarms"})
          .Build();
  extensions::ExtensionRegistry::Get(browser_context_)->AddEnabled(extension_a);
  extensions::ExtensionRegistry::Get(browser_context_)->AddEnabled(extension_b);
  RendererStartupHelperFactory::GetForBrowserContext(browser_context_)
      ->OnExtensionLoaded(*extension_a);
  RendererStartupHelperFactory::GetForBrowserContext(browser_context_)
      ->OnExtensionLoaded(*extension_b);

  auto* contents =
      static_cast<content::TestWebContents*>(test_adapter_->web_contents());
  web_contents_ = contents;
  contents->NavigateAndCommit(GURL(std::string(extensions::kExtensionScheme) +
                                   "://" + kExtensionIdA + "/index.html"));
  main_rfh_ = contents->GetPrimaryMainFrame();

  main_rfh_->InitializeRenderFrameIfNeeded();
  process_id_ = main_rfh_->GetProcess()->GetID();
  const auto extension_origin =
      extensions::Extension::CreateOriginFromExtensionId(kExtensionIdA);
  CHECK(content::ChildProcessSecurityPolicy::GetInstance()->HostsOrigin(
      static_cast<int>(process_id_), extension_origin));
  extensions::ProcessMap::Get(browser_context_)
      ->Insert(kExtensionIdA, process_id_);
}

const extensions::Extension* ExtensionFuzzerWorld::extension_a() const {
  return extensions::ExtensionRegistry::Get(browser_context_)
      ->enabled_extensions()
      .GetByID(kExtensionIdA);
}

void ExtensionFuzzerWorld::TearDown() {
  BrowserContextDependencyManager::GetInstance()
      ->DestroyBrowserContextServices(browser_context_);
  GetEnvironment().SetFuzzerContext(nullptr);
  pref_service_.reset();
  extension_pref_value_map_.reset();
  main_rfh_ = nullptr;
  web_contents_ = nullptr;
  process_id_ = content::ChildProcessId();
  browser_context_ = nullptr;
}

}  // namespace extensions::mojolpm
