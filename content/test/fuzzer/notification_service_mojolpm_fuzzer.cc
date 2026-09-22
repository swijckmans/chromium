// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "content/browser/notifications/platform_notification_context_impl.h"
#include "content/browser/renderer_host/render_frame_host_impl.h"  // nogncheck
#include "content/browser/renderer_host/render_process_host_impl.h"  // nogncheck
#include "content/browser/service_worker/embedded_worker_test_helper.h"
#include "content/browser/service_worker/service_worker_context_core.h"
#include "content/browser/service_worker/service_worker_context_wrapper_test_api.h"
#include "content/browser/service_worker/service_worker_registration.h"
#include "content/browser/storage_partition_impl.h"  // nogncheck
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/permission_result.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/content_switches.h"
#include "content/public/test/mock_permission_manager.h"
#include "content/public/test/mock_render_process_host.h"
#include "content/public/test/test_browser_context.h"
#include "content/public/test/test_renderer_host.h"
#include "content/public/test/web_contents_tester.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/fuzzer/notification_service_mojolpm_fuzzer.pb.h"
#include "content/test/mock_platform_notification_service.h"
#include "content/test/test_render_frame_host.h"
#include "content/test/test_web_contents.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/public/common/permissions/permission_utils.h"
#include "third_party/blink/public/common/service_worker/service_worker_status_code.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/frame/policy_container.mojom.h"
#include "third_party/blink/public/mojom/notifications/notification_service.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_registration_options.mojom.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"
#include "ui/aura/env.h"
#include "ui/events/devices/device_data_manager.h"
#include "ui/gfx/switches.h"
#include "ui/ozone/public/ozone_switches.h"
#include "url/gurl.h"

namespace content {

namespace {

constexpr const char* kCmdline[] = {"notification_service_mojolpm_fuzzer",
                                    nullptr};
constexpr char kTestOrigin[] = "https://example.com/";

class NotificationMockRenderProcessHost final : public MockRenderProcessHost {
 public:
  using MockRenderProcessHost::MockRenderProcessHost;

  void CreateNotificationService(
      GlobalRenderFrameHostId rfh_id,
      RenderProcessHost::NotificationServiceCreatorType creator_type,
      const blink::StorageKey& storage_key,
      mojo::PendingReceiver<blink::mojom::NotificationService> receiver)
      override {
    CHECK_CURRENTLY_ON(BrowserThread::UI);
    RenderFrameHost* rfh = RenderFrameHost::FromID(rfh_id);
    WeakDocumentPtr weak_document_ptr =
        rfh ? rfh->GetWeakDocumentPtr() : WeakDocumentPtr();
    auto* storage_partition =
        static_cast<StoragePartitionImpl*>(GetStoragePartition());
    storage_partition->GetPlatformNotificationContext()->CreateService(
        this, storage_key, rfh ? rfh->GetLastCommittedURL() : GURL(),
        weak_document_ptr, creator_type, std::move(receiver));
  }
};

class NotificationMockRenderProcessHostFactory final
    : public MockRenderProcessHostFactory {
 protected:
  std::unique_ptr<MockRenderProcessHost> BuildRenderProcessHost(
      BrowserContext* browser_context,
      SiteInstance* site_instance) override {
    const auto storage_partition_config =
        site_instance ? static_cast<SiteInstanceImpl*>(site_instance)
                            ->GetSecurityPrincipal()
                            .GetStoragePartitionConfig()
                      : StoragePartitionConfig::CreateDefault(browser_context);
    return std::make_unique<NotificationMockRenderProcessHost>(
        browser_context, storage_partition_config, false);
  }
};

mojolpm::FuzzerEnvironment& GetEnvironment() {
  static base::NoDestructor<content::mojolpm::FuzzerEnvironmentWithMainLoopIO>
      environment(1, kCmdline);
  return *environment;
}

scoped_refptr<base::SequencedTaskRunner> GetFuzzerTaskRunner() {
  return GetEnvironment().fuzzer_task_runner();
}

void DidRegisterServiceWorker(int64_t* registration_id,
                              base::OnceClosure done_closure,
                              blink::ServiceWorkerStatusCode status,
                              const std::string& status_message,
                              int64_t service_worker_registration_id) {
  CHECK_EQ(blink::ServiceWorkerStatusCode::kOk, status) << status_message;
  *registration_id = service_worker_registration_id;
  std::move(done_closure).Run();
}

}  // namespace

class NotificationServiceTestcase final
    : public ::mojolpm::Testcase<
          content::fuzzing::notification_service::proto::Testcase,
          content::fuzzing::notification_service::proto::Action> {
 public:
  using ProtoTestcase = content::fuzzing::notification_service::proto::Testcase;
  using ProtoAction = content::fuzzing::notification_service::proto::Action;

  explicit NotificationServiceTestcase(const ProtoTestcase& testcase);

  void SetUp(base::OnceClosure done_closure) override;
  void TearDown(base::OnceClosure done_closure) override;
  void RunAction(const ProtoAction& action,
                 base::OnceClosure done_closure) override;

 private:
  void SetUpOnUIThread(
      mojo::PendingReceiver<blink::mojom::NotificationService> receiver,
      base::OnceClosure done_closure);
  void RegisterServiceWorker(base::OnceClosure done_closure);
  void OnServiceWorkerRegistered(base::OnceClosure done_closure);
  void OnServiceWorkerRegistrationFound(
      base::OnceClosure done_closure,
      blink::ServiceWorkerStatusCode status,
      scoped_refptr<ServiceWorkerRegistration> registration);
  void FinishSetUpOnUIThread(
      mojo::PendingReceiver<blink::mojom::NotificationService> receiver,
      base::OnceClosure done_closure);
  void SetUpOnFuzzerThread(base::OnceClosure done_closure);
  void TearDownOnUIThread(base::OnceClosure done_closure);
  void TearDownOnFuzzerThread(base::OnceClosure done_closure);

  std::unique_ptr<TestBrowserContext> browser_context_;
  std::unique_ptr<EmbeddedWorkerTestHelper> embedded_worker_test_helper_;
  std::vector<scoped_refptr<ServiceWorkerRegistration>>
      service_worker_registrations_;
  std::unique_ptr<aura::Env> aura_env_;
  std::unique_ptr<RenderViewHostTestEnabler> rvh_enabler_;
  std::unique_ptr<NotificationMockRenderProcessHostFactory>
      render_process_host_factory_;
  raw_ptr<WebContents> web_contents_ = nullptr;
  std::unique_ptr<WebContents> web_contents_storage_;
  std::unique_ptr<testing::NiceMock<MockPermissionManager>> permission_manager_;
  mojo::Remote<blink::mojom::NotificationService> notification_service_remote_;
  int64_t service_worker_registration_id_ =
      blink::mojom::kInvalidServiceWorkerRegistrationId;
};

NotificationServiceTestcase::NotificationServiceTestcase(
    const ProtoTestcase& testcase)
    : Testcase<ProtoTestcase, ProtoAction>(testcase) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

void NotificationServiceTestcase::SetUp(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto receiver = notification_service_remote_.BindNewPipeAndPassReceiver();
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE, base::BindOnce(&NotificationServiceTestcase::SetUpOnUIThread,
                                base::Unretained(this), std::move(receiver),
                                std::move(done_closure)));
}

void NotificationServiceTestcase::SetUpOnUIThread(
    mojo::PendingReceiver<blink::mojom::NotificationService> receiver,
    base::OnceClosure done_closure) {
  base::CommandLine::ForCurrentProcess()->AppendSwitch(::switches::kHeadless);
  base::CommandLine::ForCurrentProcess()->AppendSwitchASCII(
      switches::kOzonePlatform, "headless");
  aura_env_ = aura::Env::CreateInstance();
  ui::DeviceDataManager::CreateInstance();
  browser_context_ = std::make_unique<TestBrowserContext>();
  browser_context_->SetPlatformNotificationService(
      std::make_unique<MockPlatformNotificationService>(
          browser_context_.get()));
  permission_manager_ =
      std::make_unique<testing::NiceMock<MockPermissionManager>>();
  ON_CALL(*permission_manager_, GetPermissionResultForCurrentDocument)
      .WillByDefault(testing::Return(
          PermissionResult(blink::mojom::PermissionStatus::GRANTED)));
  ON_CALL(*permission_manager_, GetPermissionResultForWorker)
      .WillByDefault(testing::Return(
          PermissionResult(blink::mojom::PermissionStatus::GRANTED)));
  browser_context_->SetPermissionControllerDelegate(
      std::move(permission_manager_));

  embedded_worker_test_helper_ =
      std::make_unique<EmbeddedWorkerTestHelper>(base::FilePath());
  auto* storage_partition = static_cast<StoragePartitionImpl*>(
      browser_context_->GetDefaultStoragePartition());
  ServiceWorkerContextWrapperTestApi(
      embedded_worker_test_helper_->context_wrapper())
      .set_storage_partition(storage_partition);

  rvh_enabler_ = std::make_unique<RenderViewHostTestEnabler>();
  render_process_host_factory_ =
      std::make_unique<NotificationMockRenderProcessHostFactory>();
  RenderProcessHostImpl::set_render_process_host_factory_for_testing(
      render_process_host_factory_.get());
  web_contents_storage_ =
      WebContentsTester::CreateTestWebContents(browser_context_.get(), nullptr);
  web_contents_ = web_contents_storage_.get();
  static_cast<TestWebContents*>(web_contents_)
      ->NavigateAndCommit(GURL(kTestOrigin));
  static_cast<TestRenderFrameHost*>(web_contents_->GetPrimaryMainFrame())
      ->InitializeRenderFrameIfNeeded();

  RegisterServiceWorker(base::BindOnce(
      &NotificationServiceTestcase::FinishSetUpOnUIThread,
      base::Unretained(this), std::move(receiver), std::move(done_closure)));
}

void NotificationServiceTestcase::RegisterServiceWorker(
    base::OnceClosure done_closure) {
  const blink::StorageKey storage_key = blink::StorageKey::CreateFirstParty(
      url::Origin::Create(GURL(kTestOrigin)));
  auto fetch_client_settings_object =
      blink::mojom::FetchClientSettingsObject::New();
  fetch_client_settings_object->policy_container_policies =
      blink::mojom::PolicyContainerPolicies::New();
  blink::mojom::ServiceWorkerRegistrationOptions options;
  options.scope = GURL(kTestOrigin);
  embedded_worker_test_helper_->context()->RegisterServiceWorker(
      GURL(std::string(kTestOrigin) + "sw.js"), storage_key, options,
      std::move(fetch_client_settings_object),
      base::BindOnce(
          &DidRegisterServiceWorker, &service_worker_registration_id_,
          base::BindOnce(
              &NotificationServiceTestcase::OnServiceWorkerRegistered,
              base::Unretained(this), std::move(done_closure))),
      /*requesting_frame_id=*/GlobalRenderFrameHostId(),
      PolicyContainerPolicies());
}

void NotificationServiceTestcase::OnServiceWorkerRegistered(
    base::OnceClosure done_closure) {
  CHECK_NE(blink::mojom::kInvalidServiceWorkerRegistrationId,
           service_worker_registration_id_);
  const blink::StorageKey storage_key = blink::StorageKey::CreateFirstParty(
      url::Origin::Create(GURL(kTestOrigin)));
  embedded_worker_test_helper_->context()->registry().FindRegistrationForId(
      service_worker_registration_id_, storage_key,
      base::BindOnce(
          &NotificationServiceTestcase::OnServiceWorkerRegistrationFound,
          base::Unretained(this), std::move(done_closure)));
}

void NotificationServiceTestcase::OnServiceWorkerRegistrationFound(
    base::OnceClosure done_closure,
    blink::ServiceWorkerStatusCode status,
    scoped_refptr<ServiceWorkerRegistration> registration) {
  CHECK_EQ(blink::ServiceWorkerStatusCode::kOk, status);
  CHECK(registration);
  service_worker_registrations_.push_back(std::move(registration));
  GetUIThreadTaskRunner({})->PostTask(FROM_HERE,
                                      base::BindOnce(
                                          [](base::OnceClosure done_closure) {
                                            base::RunLoop().RunUntilIdle();
                                            std::move(done_closure).Run();
                                          },
                                          std::move(done_closure)));
}

void NotificationServiceTestcase::FinishSetUpOnUIThread(
    mojo::PendingReceiver<blink::mojom::NotificationService> receiver,
    base::OnceClosure done_closure) {
  auto* main_rfh =
      static_cast<RenderFrameHostImpl*>(web_contents_->GetPrimaryMainFrame());
  mojo::Receiver<blink::mojom::BrowserInterfaceBroker>& broker_receiver =
      main_rfh->browser_interface_broker_receiver_for_testing();
  blink::mojom::BrowserInterfaceBroker* broker =
      broker_receiver.internal_state()->impl();
  broker->GetInterface(std::move(receiver));
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&NotificationServiceTestcase::SetUpOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void NotificationServiceTestcase::SetUpOnFuzzerThread(
    base::OnceClosure done_closure) {
  ::mojolpm::GetContext()->StartTestcase();
  ::mojolpm::GetContext()->AddInstance(0,
                                       std::move(notification_service_remote_));
  std::move(done_closure).Run();
}

void NotificationServiceTestcase::TearDown(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ::mojolpm::GetContext()->EndTestcase();
  notification_service_remote_.reset();
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&NotificationServiceTestcase::TearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void NotificationServiceTestcase::TearDownOnUIThread(
    base::OnceClosure done_closure) {
  web_contents_storage_.reset();
  web_contents_ = nullptr;
  service_worker_registrations_.clear();
  ServiceWorkerContextWrapperTestApi(
      embedded_worker_test_helper_->context_wrapper())
      .set_storage_partition(nullptr);
  embedded_worker_test_helper_.reset();
  browser_context_.reset();
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&NotificationServiceTestcase::TearDownOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void NotificationServiceTestcase::TearDownOnFuzzerThread(
    base::OnceClosure done_closure) {
  std::move(done_closure).Run();
}

void NotificationServiceTestcase::RunAction(const ProtoAction& action,
                                            base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  switch (action.action_case()) {
    case ProtoAction::kRunUntilIdle:
      base::ThreadPoolInstance::Get()->FlushForTesting();
      GetIOThreadTaskRunner({})->PostTaskAndReply(
          FROM_HERE, base::DoNothing(),
          base::BindOnce(
              [](base::OnceClosure done_closure) {
                GetUIThreadTaskRunner({})->PostTaskAndReply(
                    FROM_HERE, base::DoNothing(),
                    base::BindOnce(
                        [](base::OnceClosure done_closure) {
                          base::ThreadPoolInstance::Get()->FlushForTesting();
                          base::RunLoop().RunUntilIdle();
                          GetFuzzerTaskRunner()->PostTaskAndReply(
                              FROM_HERE, base::DoNothing(),
                              std::move(done_closure));
                        },
                        std::move(done_closure)));
              },
              std::move(done_closure)));
      return;
    case ProtoAction::kNotificationServiceRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.notification_service_remote_action());
      break;
    case ProtoAction::kNonPersistentNotificationListenerRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.non_persistent_notification_listener_remote_action());
      break;
    case ProtoAction::kNonPersistentNotificationListenerReceiverAction:
      ::mojolpm::HandleReceiverAction(
          action.non_persistent_notification_listener_receiver_action());
      break;
    case ProtoAction::ACTION_NOT_SET:
      break;
  }
  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

}  // namespace content

DEFINE_BINARY_PROTO_FUZZER(
    const content::fuzzing::notification_service::proto::Testcase&
        proto_testcase) {
  if (!proto_testcase.actions_size() || !proto_testcase.sequences_size() ||
      !proto_testcase.sequence_indexes_size()) {
    return;
  }

  content::GetEnvironment();
  content::NotificationServiceTestcase testcase(proto_testcase);
  base::RunLoop main_run_loop;
  content::GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &::mojolpm::RunTestcase<content::NotificationServiceTestcase>,
          base::Unretained(&testcase), content::GetFuzzerTaskRunner(),
          main_run_loop.QuitClosure()));
  main_run_loop.Run();
}
