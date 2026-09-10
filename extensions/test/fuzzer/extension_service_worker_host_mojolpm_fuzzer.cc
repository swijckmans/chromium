// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <memory>
#include <optional>
#include <utility>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/unguessable_token.h"
#include "content/browser/service_worker/fake_service_worker.h"
#include "content/browser/service_worker/service_worker_context_wrapper.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/service_worker_context.h"
#include "content/public/test/test_storage_partition.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/test_render_frame_host.h"
#include "extensions/browser/extension_protocols.h"
#include "extensions/browser/service_worker/service_worker_host.h"
#include "extensions/browser/service_worker/service_worker_task_queue.h"
#include "extensions/common/constants.h"
#include "extensions/common/mojom/event_dispatcher.mojom.h"
#include "extensions/common/mojom/service_worker_host.mojom-mojolpm.h"
#include "extensions/common/mojom/service_worker_host.mojom.h"
#include "extensions/test/fuzzer/extension_mojolpm_fuzzer_support.h"
#include "extensions/test/fuzzer/extension_service_worker_host_mojolpm_fuzzer.pb.h"
#include "mojo/public/cpp/bindings/associated_receiver.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/system/data_pipe_drainer.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/mojom/devtools/devtools_agent.mojom.h"
#include "third_party/blink/public/mojom/service_worker/embedded_worker.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_registration_options.mojom.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace {

using extensions::mojolpm::GetEnvironment;
using extensions::mojolpm::GetFuzzerTaskRunner;

constexpr char kServiceWorkerScope[] =
    "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/";

class FuzzerEventDispatcher : public extensions::mojom::EventDispatcher {
 public:
  FuzzerEventDispatcher() = default;
  FuzzerEventDispatcher(const FuzzerEventDispatcher&) = delete;
  FuzzerEventDispatcher& operator=(const FuzzerEventDispatcher&) = delete;
  ~FuzzerEventDispatcher() override = default;

  void DispatchEvent(extensions::mojom::DispatchEventParamsPtr params,
                     base::ListValue event_args,
                     DispatchEventCallback callback) override {
    std::move(callback).Run(false);
  }
};

class FuzzerServiceWorker : public content::FakeServiceWorker {
 public:
  FuzzerServiceWorker() : FakeServiceWorker(nullptr) {}

  FuzzerServiceWorker(const FuzzerServiceWorker&) = delete;
  FuzzerServiceWorker& operator=(const FuzzerServiceWorker&) = delete;
  ~FuzzerServiceWorker() override = default;

 protected:
  void OnConnectionError() override {}
};

class FuzzerEmbeddedWorkerInstanceClient
    : public blink::mojom::EmbeddedWorkerInstanceClient {
 public:
  class LoaderClient : public network::mojom::URLLoaderClient,
                       public mojo::DataPipeDrainer::Client {
   public:
    explicit LoaderClient(
        mojo::PendingReceiver<network::mojom::URLLoaderClient> receiver,
        mojo::ScopedDataPipeConsumerHandle body,
        base::OnceClosure callback)
        : receiver_(this, std::move(receiver)), callback_(std::move(callback)) {
      if (body.is_valid()) {
        body_drainer_ =
            std::make_unique<mojo::DataPipeDrainer>(this, std::move(body));
      }
    }

    void OnReceiveEarlyHints(
        network::mojom::EarlyHintsPtr early_hints) override {}
    void OnReceiveResponse(
        network::mojom::URLResponseHeadPtr response_head,
        mojo::ScopedDataPipeConsumerHandle body,
        std::optional<mojo_base::BigBuffer> cached_metadata) override {}
    void OnReceiveRedirect(
        const net::RedirectInfo& redirect_info,
        network::mojom::URLResponseHeadPtr response_head) override {}
    void OnUploadProgress(int64_t current_position,
                          int64_t total_size,
                          OnUploadProgressCallback ack_callback) override {}
    void OnTransferSizeUpdated(int32_t transfer_size_diff) override {}
    void OnComplete(const network::URLLoaderCompletionStatus& status) override {
      std::move(callback_).Run();
    }

   private:
    void OnDataAvailable(base::span<const uint8_t> data) override {}

    void OnDataComplete() override {}

    mojo::Receiver<network::mojom::URLLoaderClient> receiver_;
    base::OnceClosure callback_;
    std::unique_ptr<mojo::DataPipeDrainer> body_drainer_;
  };

  FuzzerEmbeddedWorkerInstanceClient() = default;
  FuzzerEmbeddedWorkerInstanceClient(
      const FuzzerEmbeddedWorkerInstanceClient&) = delete;
  FuzzerEmbeddedWorkerInstanceClient& operator=(
      const FuzzerEmbeddedWorkerInstanceClient&) = delete;
  ~FuzzerEmbeddedWorkerInstanceClient() override = default;

  void TearDown() {
    receiver_.reset();
    loader_client_.reset();
    service_worker_.reset();
    host_.reset();
    start_params_.reset();
    start_finished_ = false;
  }

  void Bind(mojo::ScopedMessagePipeHandle pipe) {
    receiver_.Bind(
        mojo::PendingReceiver<blink::mojom::EmbeddedWorkerInstanceClient>(
            std::move(pipe)));
  }

  void StartWorker(blink::mojom::EmbeddedWorkerStartParamsPtr params) override {
    loader_client_.reset();
    service_worker_.reset();
    host_.reset();
    start_params_ = std::move(params);
    host_.Bind(std::move(start_params_->instance_host));
    service_worker_ = std::make_unique<FuzzerServiceWorker>();
    service_worker_->Bind(std::move(start_params_->service_worker_receiver));
    mojo::PendingRemote<blink::mojom::DevToolsAgent> agent;
    mojo::PendingReceiver<blink::mojom::DevToolsAgent> agent_receiver =
        agent.InitWithNewPipeAndPassReceiver();
    mojo::Remote<blink::mojom::DevToolsAgentHost> devtools_agent_host;
    host_->OnReadyForInspection(
        std::move(agent), devtools_agent_host.BindNewPipeAndPassReceiver());
    if (start_params_->main_script_load_params) {
      loader_client_ = std::make_unique<LoaderClient>(
          std::move(start_params_->main_script_load_params
                        ->url_loader_client_endpoints->url_loader_client),
          std::move(start_params_->main_script_load_params->response_body),
          base::BindOnce(&FuzzerEmbeddedWorkerInstanceClient::FinishStartWorker,
                         base::Unretained(this)));
      return;
    }
    FinishStartWorker();
  }

  void FinishStartWorker() {
    if (start_finished_) {
      return;
    }
    start_finished_ = true;
    host_->OnScriptLoaded();
    host_->OnScriptEvaluationStart();
    host_->OnStarted(blink::mojom::ServiceWorkerStartStatus::kNormalCompletion,
                     blink::mojom::ServiceWorkerFetchHandlerType::kNotSkippable,
                     /*has_hid_event_handlers=*/false,
                     /*has_usb_event_handlers=*/false, /*thread_id=*/1,
                     blink::mojom::EmbeddedWorkerStartTiming::New());
    host_.FlushForTesting();
  }

  void StopWorker() override {
    host_->OnStopped();
    receiver_.reset();
  }

 private:
  mojo::Receiver<blink::mojom::EmbeddedWorkerInstanceClient> receiver_{this};
  mojo::AssociatedRemote<blink::mojom::EmbeddedWorkerInstanceHost> host_;
  blink::mojom::EmbeddedWorkerStartParamsPtr start_params_;
  std::unique_ptr<FuzzerServiceWorker> service_worker_;
  std::unique_ptr<LoaderClient> loader_client_;
  bool start_finished_ = false;
};

}  // namespace

class ServiceWorkerHostTestcase
    : public mojolpm::Testcase<
          extensions::fuzzing::extension_service_worker_host::proto::Testcase,
          extensions::fuzzing::extension_service_worker_host::proto::Action> {
 public:
  using ProtoTestcase =
      extensions::fuzzing::extension_service_worker_host::proto::Testcase;
  using ProtoAction =
      extensions::fuzzing::extension_service_worker_host::proto::Action;

  explicit ServiceWorkerHostTestcase(const ProtoTestcase& testcase);
  ~ServiceWorkerHostTestcase();

  void SetUp(base::OnceClosure done_closure) override;
  void TearDown(base::OnceClosure done_closure) override;
  void RunAction(const ProtoAction& action,
                 base::OnceClosure done_closure) override;

 private:
  void SetUpOnUIThread(base::OnceClosure done_closure);
  void SetUpOnFuzzerThread(base::OnceClosure done_closure);
  void TearDownOnUIThread(base::OnceClosure done_closure);
  void FinishTearDownOnUIThread(base::OnceClosure done_closure);
  void AddServiceWorkerHost(uint32_t id, base::OnceClosure done_closure);
  void BindServiceWorkerHost(
      mojo::PendingAssociatedReceiver<extensions::mojom::ServiceWorkerHost>
          receiver);
  void AddServiceWorkerHostInstance(
      uint32_t id,
      mojo::AssociatedRemote<extensions::mojom::ServiceWorkerHost> remote,
      base::OnceClosure done_closure);
  void RegisterWorker(const extensions::fuzzing::extension_service_worker_host::
                          proto::RegisterWorkerAction& action,
                      base::OnceClosure done_closure);
  void RegisterContentWorker(base::OnceClosure done_closure);
  void StartContentWorker(base::OnceClosure done_closure);
  void FinishContentWorker(base::OnceClosure done_closure,
                           int64_t version_id,
                           content::ChildProcessId process_id,
                           int thread_id,
                           const blink::ServiceWorkerToken& token);

  content::mojolpm::RenderViewHostTestHarnessAdapter test_adapter_;
  extensions::mojolpm::ExtensionFuzzerWorld world_{&test_adapter_};
  FuzzerEventDispatcher event_dispatcher_;
  mojo::AssociatedReceiver<extensions::mojom::EventDispatcher>
      event_dispatcher_receiver_{&event_dispatcher_};
  FuzzerEmbeddedWorkerInstanceClient embedded_worker_client_;
  base::UnguessableToken activation_token_;
  blink::ServiceWorkerToken worker_token_;
  int64_t registered_version_id_ = 0;
  int registered_thread_id_ = 1;
};

ServiceWorkerHostTestcase::ServiceWorkerHostTestcase(
    const ProtoTestcase& testcase)
    : Testcase<ProtoTestcase, ProtoAction>(testcase) {
  test_adapter_.SetUp();
}

ServiceWorkerHostTestcase::~ServiceWorkerHostTestcase() {
  test_adapter_.TearDown();
}

void ServiceWorkerHostTestcase::SetUp(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  content::GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&ServiceWorkerHostTestcase::SetUpOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ServiceWorkerHostTestcase::SetUpOnUIThread(
    base::OnceClosure done_closure) {
  world_.SetUp();
  auto* process_host = static_cast<content::MockRenderProcessHost*>(
      world_.main_rfh()->GetProcess());
  process_host->OverrideBinderForTesting(
      blink::mojom::EmbeddedWorkerInstanceClient::Name_,
      base::BindRepeating(&FuzzerEmbeddedWorkerInstanceClient::Bind,
                          base::Unretained(&embedded_worker_client_)));
  auto* task_queue =
      extensions::ServiceWorkerTaskQueue::Get(world_.browser_context());
  task_queue->ActivateExtension(world_.extension_a());
  std::optional<base::UnguessableToken> token =
      task_queue->GetCurrentActivationToken(extensions::mojolpm::kExtensionIdA);
  CHECK(token) << "Service worker activation token was not created";
  activation_token_ = *token;
  RegisterContentWorker(std::move(done_closure));
}

void ServiceWorkerHostTestcase::RegisterContentWorker(
    base::OnceClosure done_closure) {
  auto* storage_partition = static_cast<content::TestStoragePartition*>(
      test_adapter_.browser_context()->GetDefaultStoragePartition());
  auto* context = storage_partition->GetServiceWorkerContext();
  auto* context_wrapper =
      static_cast<content::ServiceWorkerContextWrapper*>(context);
  context_wrapper->SetLoaderFactoryForUpdateCheckForTest(
      base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
          extensions::CreateExtensionServiceWorkerScriptURLLoaderFactory(
              world_.browser_context())));
  blink::mojom::ServiceWorkerRegistrationOptions options;
  options.scope = GURL(kServiceWorkerScope);
  const GURL script_url =
      GURL("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sw.js");
  const blink::StorageKey key = blink::StorageKey::CreateFirstParty(
      url::Origin::Create(GURL(kServiceWorkerScope)));
  context->RegisterServiceWorker(
      script_url, key, options, world_.main_rfh()->GetGlobalId(),
      base::BindOnce(
          [](ServiceWorkerHostTestcase* testcase,
             base::OnceClosure done_closure,
             blink::ServiceWorkerStatusCode status) {
            CHECK_EQ(status, blink::ServiceWorkerStatusCode::kOk);
            testcase->StartContentWorker(std::move(done_closure));
          },
          base::Unretained(this), std::move(done_closure)));
}

void ServiceWorkerHostTestcase::StartContentWorker(
    base::OnceClosure done_closure) {
  auto* storage_partition = static_cast<content::TestStoragePartition*>(
      test_adapter_.browser_context()->GetDefaultStoragePartition());
  auto* context = storage_partition->GetServiceWorkerContext();
  const blink::StorageKey key = blink::StorageKey::CreateFirstParty(
      url::Origin::Create(GURL(kServiceWorkerScope)));
  context->StartWorkerForScope(
      GURL(kServiceWorkerScope), key,
      base::BindOnce(&ServiceWorkerHostTestcase::FinishContentWorker,
                     base::Unretained(this), std::move(done_closure)),
      base::BindOnce([](content::StatusCodeResponse response) {
        CHECK_EQ(response.status_code, blink::ServiceWorkerStatusCode::kOk);
      }));
}

void ServiceWorkerHostTestcase::FinishContentWorker(
    base::OnceClosure done_closure,
    int64_t version_id,
    content::ChildProcessId process_id,
    int thread_id,
    const blink::ServiceWorkerToken& token) {
  registered_version_id_ = version_id;
  registered_thread_id_ = thread_id;
  worker_token_ = token;
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ServiceWorkerHostTestcase::SetUpOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ServiceWorkerHostTestcase::SetUpOnFuzzerThread(
    base::OnceClosure done_closure) {
  mojolpm::GetContext()->StartTestcase();
  std::move(done_closure).Run();
}

void ServiceWorkerHostTestcase::TearDown(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  mojolpm::GetContext()->EndTestcase();
  content::GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&ServiceWorkerHostTestcase::TearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ServiceWorkerHostTestcase::TearDownOnUIThread(
    base::OnceClosure done_closure) {
  auto* storage_partition = static_cast<content::TestStoragePartition*>(
      test_adapter_.browser_context()->GetDefaultStoragePartition());
  auto* context_wrapper = static_cast<content::ServiceWorkerContextWrapper*>(
      storage_partition->GetServiceWorkerContext());
  context_wrapper->ClearAllServiceWorkersForTest(
      base::BindOnce(&ServiceWorkerHostTestcase::FinishTearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void ServiceWorkerHostTestcase::FinishTearDownOnUIThread(
    base::OnceClosure done_closure) {
  event_dispatcher_receiver_.reset();
  embedded_worker_client_.TearDown();
  world_.TearDown();
  base::RunLoop run_loop(base::RunLoop::Type::kNestableTasksAllowed);
  run_loop.RunUntilIdle();
  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

void ServiceWorkerHostTestcase::RunAction(const ProtoAction& action,
                                          base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  switch (action.action_case()) {
    case ProtoAction::kNewServiceWorkerHost:
      AddServiceWorkerHost(action.new_service_worker_host().id(),
                           std::move(done_closure));
      return;
    case ProtoAction::kRegisterWorker:
      RegisterWorker(action.register_worker(), std::move(done_closure));
      return;
    case ProtoAction::kRunUntilIdle:
      content::GetUIThreadTaskRunner({})->PostTaskAndReply(
          FROM_HERE, base::BindOnce([]() {
            base::RunLoop run_loop(base::RunLoop::Type::kNestableTasksAllowed);
            run_loop.RunUntilIdle();
          }),
          std::move(done_closure));
      return;
    case ProtoAction::kServiceWorkerHostAssociatedRemoteAction:
      mojolpm::HandleAssociatedRemoteAction(
          action.service_worker_host_associated_remote_action());
      break;
    case ProtoAction::ACTION_NOT_SET:
      break;
  }
  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

void ServiceWorkerHostTestcase::AddServiceWorkerHost(
    uint32_t id,
    base::OnceClosure done_closure) {
  mojo::AssociatedRemote<extensions::mojom::ServiceWorkerHost> remote;
  auto receiver = remote.BindNewEndpointAndPassDedicatedReceiver();
  content::GetUIThreadTaskRunner({})->PostTaskAndReply(
      FROM_HERE,
      base::BindOnce(&ServiceWorkerHostTestcase::BindServiceWorkerHost,
                     base::Unretained(this), std::move(receiver)),
      base::BindOnce(&ServiceWorkerHostTestcase::AddServiceWorkerHostInstance,
                     base::Unretained(this), id, std::move(remote),
                     std::move(done_closure)));
}

void ServiceWorkerHostTestcase::BindServiceWorkerHost(
    mojo::PendingAssociatedReceiver<extensions::mojom::ServiceWorkerHost>
        receiver) {
  extensions::ServiceWorkerHost::BindReceiver(world_.render_process_id(),
                                              std::move(receiver));
}

void ServiceWorkerHostTestcase::AddServiceWorkerHostInstance(
    uint32_t id,
    mojo::AssociatedRemote<extensions::mojom::ServiceWorkerHost> remote,
    base::OnceClosure done_closure) {
  mojolpm::GetContext()->AddInstance(id, std::move(remote));
  std::move(done_closure).Run();
}

void ServiceWorkerHostTestcase::RegisterWorker(
    const extensions::fuzzing::extension_service_worker_host::proto::
        RegisterWorkerAction& action,
    base::OnceClosure done_closure) {
  if (action.has_version_id()) {
    registered_version_id_ = action.version_id();
  }
  if (action.has_thread_id()) {
    registered_thread_id_ = action.thread_id();
  }
  if (registered_thread_id_ == extensions::kMainThreadId) {
    registered_thread_id_ = 1;
  }
  auto* remote =
      mojolpm::GetContext()
          ->GetInstance<
              mojo::AssociatedRemote<extensions::mojom::ServiceWorkerHost>>(
              action.id());
  if (remote) {
    event_dispatcher_receiver_.reset();
    auto event_remote =
        event_dispatcher_receiver_.BindNewEndpointAndPassRemote();
    remote->get()->DidInitializeServiceWorkerContext(
        extensions::mojolpm::kExtensionIdA, activation_token_,
        registered_version_id_, registered_thread_id_, worker_token_,
        std::move(event_remote));
    remote->get()->DidStartServiceWorkerContext(
        extensions::mojolpm::kExtensionIdA, activation_token_,
        GURL(kServiceWorkerScope), registered_version_id_,
        registered_thread_id_, worker_token_);
  }
  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

DEFINE_BINARY_PROTO_FUZZER(
    const extensions::fuzzing::extension_service_worker_host::proto::Testcase&
        proto_testcase) {
  if (!proto_testcase.actions_size() || !proto_testcase.sequences_size() ||
      !proto_testcase.sequence_indexes_size()) {
    return;
  }

  GetEnvironment();
  ServiceWorkerHostTestcase testcase(proto_testcase);

  base::RunLoop main_run_loop;
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&mojolpm::RunTestcase<ServiceWorkerHostTestcase>,
                     base::Unretained(&testcase), GetFuzzerTaskRunner(),
                     main_run_loop.QuitClosure()));
  main_run_loop.Run();
}
