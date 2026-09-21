// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "components/services/storage/public/mojom/cache_storage_control.mojom.h"
#include "content/browser/buckets/bucket_manager.h"                // nogncheck
#include "content/browser/renderer_host/render_frame_host_impl.h"  // nogncheck
#include "content/browser/storage_partition_impl.h"                // nogncheck
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/mock_render_process_host.h"
#include "content/public/test/test_browser_context.h"
#include "content/public/test/test_renderer_host.h"
#include "content/public/test/web_contents_tester.h"
#include "content/test/fuzzer/bucket_manager_host_mojolpm_fuzzer.pb.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/test_render_frame_host.h"
#include "content/test/test_render_view_host_factory.h"
#include "content/test/test_web_contents.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/mojom/buckets/bucket_manager_host.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/cache_storage/cache_storage.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_directory_handle.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_handle.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/locks/lock_manager.mojom-mojolpm.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"
#include "ui/aura/env.h"
#include "ui/events/devices/device_data_manager.h"
#include "url/gurl.h"

namespace content {

namespace {

constexpr const char* kCmdline[] = {"bucket_manager_host_mojolpm_fuzzer",
                                    nullptr};
constexpr char kTestUrl[] = "https://example.com/";

mojolpm::FuzzerEnvironment& GetEnvironment() {
  static base::NoDestructor<
      content::mojolpm::FuzzerEnvironmentWithTaskEnvironment>
      environment(1, kCmdline);
  return *environment;
}

scoped_refptr<base::SequencedTaskRunner> GetFuzzerTaskRunner() {
  return GetEnvironment().fuzzer_task_runner();
}

}  // namespace

class BucketMockRenderProcessHost final : public MockRenderProcessHost {
 public:
  BucketMockRenderProcessHost(BrowserContext* browser_context,
                              SiteInstance* site_instance)
      : MockRenderProcessHost(
            browser_context,
            StoragePartitionConfig::CreateDefault(browser_context),
            site_instance && site_instance->GetSecurityPrincipal().IsGuest()) {}

  void BindBucketManagerHost(
      base::WeakPtr<BucketContext> bucket_context,
      mojo::PendingReceiver<blink::mojom::BucketManagerHost> receiver)
      override {
    static_cast<StoragePartitionImpl*>(GetStoragePartition())
        ->GetBucketManager()
        ->BindReceiver(std::move(bucket_context), std::move(receiver),
                       base::BindOnce([](std::string_view) {}));
  }

  void BindCacheStorage(
      const network::CrossOriginEmbedderPolicy& coep_policy,
      mojo::PendingRemote<network::mojom::CrossOriginEmbedderPolicyReporter>
          coep_reporter,
      const network::DocumentIsolationPolicy& dip_policy,
      mojo::PendingRemote<network::mojom::DocumentIsolationPolicyReporter>
          dip_reporter,
      const storage::BucketLocator& bucket_locator,
      mojo::PendingReceiver<blink::mojom::CacheStorage> receiver) override {
    static_cast<StoragePartitionImpl*>(GetStoragePartition())
        ->GetCacheStorageControl()
        ->AddReceiver(coep_policy, std::move(coep_reporter), dip_policy,
                      std::move(dip_reporter), bucket_locator,
                      storage::mojom::CacheStorageOwner::kCacheAPI,
                      std::move(receiver));
  }
};

class BucketMockRenderProcessHostFactory final
    : public MockRenderProcessHostFactory {
 protected:
  std::unique_ptr<MockRenderProcessHost> BuildRenderProcessHost(
      BrowserContext* browser_context,
      SiteInstance* site_instance) override {
    return std::make_unique<BucketMockRenderProcessHost>(browser_context,
                                                         site_instance);
  }
};

class BucketRenderViewHostTestEnabler final : public RenderViewHostTestEnabler {
 public:
  BucketRenderViewHostTestEnabler() {
    rvh_factory_.reset();
    rph_factory_ = std::make_unique<BucketMockRenderProcessHostFactory>();
    rvh_factory_ = std::make_unique<TestRenderViewHostFactory>(
        rph_factory_.get(), asgh_factory_.get());
  }
};

class BucketManagerHostTestcase
    : public ::mojolpm::Testcase<
          content::fuzzing::bucket_manager_host::proto::Testcase,
          content::fuzzing::bucket_manager_host::proto::Action> {
 public:
  using ProtoTestcase = content::fuzzing::bucket_manager_host::proto::Testcase;
  using ProtoAction = content::fuzzing::bucket_manager_host::proto::Action;

  explicit BucketManagerHostTestcase(const ProtoTestcase& testcase);

  void SetUp(base::OnceClosure done_closure) override;
  void TearDown(base::OnceClosure done_closure) override;
  void RunAction(const ProtoAction& action,
                 base::OnceClosure done_closure) override;

 private:
  void SetUpOnUIThread(base::OnceClosure done_closure);
  void SetUpOnFuzzerThread(base::OnceClosure done_closure);
  void TearDownOnUIThread(base::OnceClosure done_closure);
  void TearDownOnFuzzerThread(base::OnceClosure done_closure);

  std::unique_ptr<TestBrowserContext> browser_context_;
  std::unique_ptr<aura::Env> aura_env_;
  std::unique_ptr<BucketRenderViewHostTestEnabler> rvh_enabler_;
  raw_ptr<WebContents> web_contents_ = nullptr;
  std::unique_ptr<WebContents> web_contents_storage_;
  mojo::Remote<blink::mojom::BucketManagerHost> bucket_manager_remote_;
  mojo::PendingReceiver<blink::mojom::BucketManagerHost>
      bucket_manager_receiver_;
};

BucketManagerHostTestcase::BucketManagerHostTestcase(
    const ProtoTestcase& testcase)
    : Testcase<ProtoTestcase, ProtoAction>(testcase) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

void BucketManagerHostTestcase::SetUp(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bucket_manager_receiver_ =
      bucket_manager_remote_.BindNewPipeAndPassReceiver();
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&BucketManagerHostTestcase::SetUpOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void BucketManagerHostTestcase::SetUpOnUIThread(
    base::OnceClosure done_closure) {
  aura_env_ = aura::Env::CreateInstance();
  ui::DeviceDataManager::CreateInstance();
  browser_context_ = std::make_unique<TestBrowserContext>();
  rvh_enabler_ = std::make_unique<BucketRenderViewHostTestEnabler>();
  web_contents_storage_ =
      WebContentsTester::CreateTestWebContents(browser_context_.get(), nullptr);
  web_contents_ = web_contents_storage_.get();
  static_cast<TestWebContents*>(web_contents_)
      ->NavigateAndCommit(GURL(kTestUrl));
  static_cast<TestRenderFrameHost*>(web_contents_->GetPrimaryMainFrame())
      ->InitializeRenderFrameIfNeeded();

  auto* main_rfh = web_contents_->GetPrimaryMainFrame();
  static_cast<RenderFrameHostImpl*>(main_rfh)->CreateBucketManagerHost(
      std::move(bucket_manager_receiver_));

  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&BucketManagerHostTestcase::SetUpOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void BucketManagerHostTestcase::SetUpOnFuzzerThread(
    base::OnceClosure done_closure) {
  ::mojolpm::GetContext()->StartTestcase();
  ::mojolpm::GetContext()->AddInstance(0, std::move(bucket_manager_remote_));
  std::move(done_closure).Run();
}

void BucketManagerHostTestcase::TearDown(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ::mojolpm::GetContext()->EndTestcase();
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&BucketManagerHostTestcase::TearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void BucketManagerHostTestcase::TearDownOnUIThread(
    base::OnceClosure done_closure) {
  web_contents_storage_.reset();
  web_contents_ = nullptr;
  browser_context_.reset();
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&BucketManagerHostTestcase::TearDownOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void BucketManagerHostTestcase::TearDownOnFuzzerThread(
    base::OnceClosure done_closure) {
  std::move(done_closure).Run();
}

void BucketManagerHostTestcase::RunAction(const ProtoAction& action,
                                          base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  switch (action.action_case()) {
    case ProtoAction::kRunUntilIdle:  // nocheck
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
    case ProtoAction::kBucketManagerHostRemoteAction:
      ::mojolpm::HandleRemoteAction(action.bucket_manager_host_remote_action());
      break;
    case ProtoAction::kBucketHostRemoteAction:
      ::mojolpm::HandleRemoteAction(action.bucket_host_remote_action());
      break;
    case ProtoAction::kCacheStorageRemoteAction:
      ::mojolpm::HandleRemoteAction(action.cache_storage_remote_action());
      break;
    case ProtoAction::kCacheStorageCacheRemoteAction:
      ::mojolpm::HandleAssociatedRemoteAction(
          action.cache_storage_cache_remote_action());
      break;
    case ProtoAction::kIdbFactoryRemoteAction:
      ::mojolpm::HandleRemoteAction(action.idb_factory_remote_action());
      break;
    case ProtoAction::kLockManagerRemoteAction:
      ::mojolpm::HandleRemoteAction(action.lock_manager_remote_action());
      break;
    case ProtoAction::kFileSystemAccessDirectoryHandleRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_directory_handle_remote_action());
      break;
    case ProtoAction::kFileSystemAccessFileHandleRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_file_handle_remote_action());
      break;
    case ProtoAction::ACTION_NOT_SET:
      break;
  }

  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

}  // namespace content

DEFINE_BINARY_PROTO_FUZZER(
    const content::fuzzing::bucket_manager_host::proto::Testcase&
        proto_testcase) {
  if (!proto_testcase.actions_size() || !proto_testcase.sequences_size() ||
      !proto_testcase.sequence_indexes_size()) {
    return;
  }

  content::GetEnvironment();
  content::BucketManagerHostTestcase testcase(proto_testcase);
  base::RunLoop main_run_loop;
  content::GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &::mojolpm::RunTestcase<content::BucketManagerHostTestcase>,
          base::Unretained(&testcase), content::GetFuzzerTaskRunner(),
          main_run_loop.QuitClosure()));
  main_run_loop.Run();
}
