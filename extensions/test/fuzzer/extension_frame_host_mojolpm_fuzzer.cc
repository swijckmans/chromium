// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "components/prefs/pref_service.h"
#include "components/prefs/pref_service_factory.h"
#include "components/prefs/testing_pref_store.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/child_process_security_policy.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/test/test_browser_context.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/test_render_frame_host.h"
#include "content/test/test_web_contents.h"
#include "extensions/browser/api/core_extensions_browser_api_provider.h"
#include "extensions/browser/api/alarms/alarm_manager.h"
#include "extensions/browser/api/extensions_api_client.h"
#include "extensions/browser/core_browser_context_keyed_service_factories.h"
#include "extensions/browser/extension_frame_host.h"
#include "extensions/browser/extension_pref_value_map.h"
#include "extensions/browser/extension_prefs.h"
#include "extensions/browser/extension_prefs_factory.h"
#include "extensions/browser/extension_function_registry.h"
#include "extensions/browser/extension_registry.h"
#include "extensions/browser/extension_web_contents_observer.h"
#include "extensions/browser/mock_extension_system.h"
#include "extensions/browser/permissions_manager.h"
#include "extensions/browser/process_map.h"
#include "extensions/browser/process_map_factory.h"
#include "extensions/browser/quota_service.h"
#include "extensions/browser/test_extensions_browser_client.h"
#include "extensions/common/constants.h"
#include "extensions/common/extension.h"
#include "extensions/common/extension_builder.h"
#include "extensions/common/extensions_client.h"
#include "extensions/common/mojom/frame.mojom-mojolpm.h"
#include "extensions/common/mojom/frame.mojom.h"
#include "extensions/common/mojom/context_type.mojom.h"
#include "extensions/test/fuzzer/extension_frame_host_mojolpm_fuzzer.pb.h"
#include "extensions/test/test_extensions_client.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"
#include "url/gurl.h"

namespace {

constexpr char kExtensionIdA[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr char kExtensionIdB[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr const char* kCmdline[] = {"extension_frame_host_mojolpm_fuzzer",
                                    nullptr};

class FuzzerExtensionsBrowserClient : public extensions::TestExtensionsBrowserClient {
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

class FuzzerExtensionWebContentsObserver
    : public extensions::ExtensionWebContentsObserver {
 public:
  explicit FuzzerExtensionWebContentsObserver(content::WebContents* web_contents)
      : ExtensionWebContentsObserver(web_contents) {}
};

class FuzzerMockExtensionSystem : public extensions::MockExtensionSystem {
 public:
  explicit FuzzerMockExtensionSystem(content::BrowserContext* context)
      : MockExtensionSystem(context), quota_service_(std::make_unique<
                                                   extensions::QuotaService>()) {}

  extensions::QuotaService* quota_service() override {
    return quota_service_.get();
  }

 private:
  std::unique_ptr<extensions::QuotaService> quota_service_;
};

class ExtensionsFuzzerEnvironment
    : public content::mojolpm::FuzzerEnvironment {
 public:
  ExtensionsFuzzerEnvironment()
      : content::mojolpm::FuzzerEnvironment(1, kCmdline),
        browser_client_() {
    extensions::ExtensionsClient::Set(&extensions_client_);
    browser_client_.set_extension_system_factory(&extension_system_factory_);
    extensions::ExtensionsBrowserClient::Set(&browser_client_);
    ExtensionFunctionRegistry::GetInstance();
  }

  ~ExtensionsFuzzerEnvironment() override {
    extensions::ExtensionsBrowserClient::Set(nullptr);
    extensions::ExtensionsClient::Set(nullptr);
  }

  FuzzerExtensionsBrowserClient* browser_client() { return &browser_client_; }

 private:
  extensions::TestExtensionsClient extensions_client_;
  extensions::ExtensionsAPIClient extensions_api_client_;
  FuzzerExtensionsBrowserClient browser_client_;
  extensions::MockExtensionSystemFactory<FuzzerMockExtensionSystem>
      extension_system_factory_;
};

ExtensionsFuzzerEnvironment& GetEnvironment() {
  static base::NoDestructor<ExtensionsFuzzerEnvironment> environment;
  return *environment;
}

scoped_refptr<base::SequencedTaskRunner> GetFuzzerTaskRunner() {
  return GetEnvironment().fuzzer_task_runner();
}

}  // namespace

class ExtensionFrameHostTestcase
    : public mojolpm::Testcase<
          extensions::fuzzing::extension_frame_host::proto::Testcase,
          extensions::fuzzing::extension_frame_host::proto::Action> {
 public:
  using ProtoTestcase =
      extensions::fuzzing::extension_frame_host::proto::Testcase;
  using ProtoAction = extensions::fuzzing::extension_frame_host::proto::Action;

  explicit ExtensionFrameHostTestcase(const ProtoTestcase& testcase);
  ~ExtensionFrameHostTestcase();

  void SetUp(base::OnceClosure done_closure) override;
  void TearDown(base::OnceClosure done_closure) override;
  void RunAction(const ProtoAction& action,
                 base::OnceClosure done_closure) override;

 private:
  void SetUpOnUIThread(base::OnceClosure done_closure);
  void SetUpOnFuzzerThread(base::OnceClosure done_closure);
  void TearDownOnUIThread(base::OnceClosure done_closure);
  void AddLocalFrameHost(uint32_t id, base::OnceClosure done_closure);
  void BindLocalFrameHost(
      mojo::PendingAssociatedReceiver<extensions::mojom::LocalFrameHost>
          receiver);
  void AddLocalFrameHostInstance(
      uint32_t id,
      mojo::AssociatedRemote<extensions::mojom::LocalFrameHost> remote,
      base::OnceClosure done_closure);

  content::mojolpm::RenderViewHostTestHarnessAdapter test_adapter_;
  raw_ptr<content::TestRenderFrameHost> render_frame_host_ = nullptr;
  std::unique_ptr<extensions::ExtensionFrameHost> extension_frame_host_;
  std::unique_ptr<FuzzerExtensionWebContentsObserver> observer_;
  std::unique_ptr<ExtensionPrefValueMap> extension_pref_value_map_;
  std::unique_ptr<PrefService> pref_service_;
};

ExtensionFrameHostTestcase::ExtensionFrameHostTestcase(
    const ProtoTestcase& testcase)
    : Testcase<ProtoTestcase, ProtoAction>(testcase) {
  test_adapter_.SetUp();
}

ExtensionFrameHostTestcase::~ExtensionFrameHostTestcase() {
  test_adapter_.TearDown();
}

void ExtensionFrameHostTestcase::SetUp(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  content::GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&ExtensionFrameHostTestcase::SetUpOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ExtensionFrameHostTestcase::SetUpOnUIThread(
    base::OnceClosure done_closure) {
  auto* browser_context = test_adapter_.browser_context();
  GetEnvironment().browser_client()->SetFuzzerContext(browser_context);
  extensions::EnsureCoreBrowserContextKeyedServiceFactoriesBuilt();
  extensions::ProcessMapFactory::GetInstance();
  extensions::AlarmManager::GetFactoryInstance();
  BrowserContextDependencyManager::GetInstance()->MarkBrowserContextLive(
      browser_context);

  extension_pref_value_map_ =
      std::make_unique<ExtensionPrefValueMap>();
  PrefServiceFactory pref_service_factory;
  pref_service_factory.set_user_prefs(new TestingPrefStore());
  pref_service_factory.set_extension_prefs(new TestingPrefStore());
  auto* pref_registry = new user_prefs::PrefRegistrySyncable();
  extensions::ExtensionPrefs::RegisterProfilePrefs(pref_registry);
  extensions::PermissionsManager::RegisterProfilePrefs(pref_registry);
  pref_service_ = pref_service_factory.Create(pref_registry);
  extensions::ExtensionPrefsFactory::GetInstance()->SetInstanceForTesting(
      browser_context,
      extensions::ExtensionPrefs::Create(
          browser_context, pref_service_.get(),
          browser_context->GetPath().AppendASCII("Extensions"),
          extension_pref_value_map_.get(), false /* extensions_disabled */,
          std::vector<extensions::EarlyExtensionPrefsObserver*>()));

  BrowserContextDependencyManager::GetInstance()
      ->CreateBrowserContextServicesForTest(browser_context);

  auto extension_a =
      extensions::ExtensionBuilder("Extension A")
          .SetID(kExtensionIdA)
          .AddAPIPermissions({"storage", "alarms"})
          .Build();
  auto extension_b =
      extensions::ExtensionBuilder("Extension B")
          .SetID(kExtensionIdB)
          .AddAPIPermissions({"storage", "alarms"})
          .Build();
  extensions::ExtensionRegistry::Get(browser_context)->AddEnabled(extension_a);
  extensions::ExtensionRegistry::Get(browser_context)->AddEnabled(extension_b);

  auto* contents = static_cast<content::TestWebContents*>(
      test_adapter_.web_contents());
  contents->NavigateAndCommit(
      GURL(std::string(extensions::kExtensionScheme) + "://" + kExtensionIdA +
           "/index.html"));
  render_frame_host_ = contents->GetPrimaryMainFrame();

  render_frame_host_->InitializeRenderFrameIfNeeded();
  const auto process_id = render_frame_host_->GetProcess()->GetID();
  const auto extension_origin =
      extensions::Extension::CreateOriginFromExtensionId(kExtensionIdA);
  CHECK(content::ChildProcessSecurityPolicy::GetInstance()->HostsOrigin(
      static_cast<int>(process_id), extension_origin));
  extensions::ProcessMap::Get(browser_context)->Insert(kExtensionIdA,
                                                       process_id);

  extension_frame_host_ =
      std::make_unique<extensions::ExtensionFrameHost>(contents);
  observer_ =
      std::make_unique<FuzzerExtensionWebContentsObserver>(contents);
  GetEnvironment().browser_client()->SetFuzzerObserver(observer_.get());

  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ExtensionFrameHostTestcase::SetUpOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ExtensionFrameHostTestcase::SetUpOnFuzzerThread(
    base::OnceClosure done_closure) {
  mojolpm::GetContext()->StartTestcase();
  std::move(done_closure).Run();
}

void ExtensionFrameHostTestcase::TearDown(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  mojolpm::GetContext()->EndTestcase();
  content::GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&ExtensionFrameHostTestcase::TearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ExtensionFrameHostTestcase::TearDownOnUIThread(
    base::OnceClosure done_closure) {
  extension_frame_host_.reset();
  GetEnvironment().browser_client()->SetFuzzerObserver(nullptr);
  observer_.reset();
  BrowserContextDependencyManager::GetInstance()
      ->DestroyBrowserContextServices(test_adapter_.browser_context());
  GetEnvironment().browser_client()->SetFuzzerContext(nullptr);
  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

void ExtensionFrameHostTestcase::RunAction(const ProtoAction& action,
                                           base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  switch (action.action_case()) {
    case ProtoAction::kNewLocalFrameHost:
      AddLocalFrameHost(action.new_local_frame_host().id(),
                        std::move(done_closure));
      return;
    case ProtoAction::kRunUntilIdle:
      content::GetUIThreadTaskRunner({})->PostTaskAndReply(
          FROM_HERE, base::DoNothing(), std::move(done_closure));
      return;
    case ProtoAction::kLocalFrameHostAssociatedRemoteAction:
      mojolpm::HandleAssociatedRemoteAction(
          action.local_frame_host_associated_remote_action());
      break;
    case ProtoAction::ACTION_NOT_SET:
      break;
  }
  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

void ExtensionFrameHostTestcase::AddLocalFrameHost(
    uint32_t id,
    base::OnceClosure done_closure) {
  mojo::AssociatedRemote<extensions::mojom::LocalFrameHost> remote;
  auto receiver = remote.BindNewEndpointAndPassDedicatedReceiver();
  content::GetUIThreadTaskRunner({})->PostTaskAndReply(
      FROM_HERE,
      base::BindOnce(&ExtensionFrameHostTestcase::BindLocalFrameHost,
                     base::Unretained(this), std::move(receiver)),
      base::BindOnce(&ExtensionFrameHostTestcase::AddLocalFrameHostInstance,
                     base::Unretained(this), id, std::move(remote),
                     std::move(done_closure)));
}

void ExtensionFrameHostTestcase::BindLocalFrameHost(
    mojo::PendingAssociatedReceiver<extensions::mojom::LocalFrameHost>
        receiver) {
  extension_frame_host_->BindLocalFrameHost(std::move(receiver),
                                            render_frame_host_);
}

void ExtensionFrameHostTestcase::AddLocalFrameHostInstance(
    uint32_t id,
    mojo::AssociatedRemote<extensions::mojom::LocalFrameHost> remote,
    base::OnceClosure done_closure) {
  mojolpm::GetContext()->AddInstance(id, std::move(remote));
  std::move(done_closure).Run();
}

DEFINE_BINARY_PROTO_FUZZER(
    const extensions::fuzzing::extension_frame_host::proto::Testcase&
        proto_testcase) {
  if (!proto_testcase.actions_size() || !proto_testcase.sequences_size() ||
      !proto_testcase.sequence_indexes_size()) {
    return;
  }

  GetEnvironment();
  ExtensionFrameHostTestcase testcase(proto_testcase);

  base::RunLoop main_run_loop;
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&mojolpm::RunTestcase<ExtensionFrameHostTestcase>,
                     base::Unretained(&testcase), GetFuzzerTaskRunner(),
                     main_run_loop.QuitClosure()));
  main_run_loop.Run();
}
