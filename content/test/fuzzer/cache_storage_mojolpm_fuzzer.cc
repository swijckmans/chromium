// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "content/browser/storage_partition_impl.h"  // nogncheck
#include "content/public/browser/web_contents.h"
#include "content/browser/renderer_host/render_frame_host_impl.h"  // nogncheck
#include "content/public/browser/browser_task_traits.h"
#include "content/public/test/test_browser_context.h"
#include "content/public/test/test_web_contents_factory.h"
#include "content/test/fuzzer/cache_storage_mojolpm_fuzzer.pb.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/test_render_frame_host.h"
#include "content/test/test_web_contents.h"
#include "components/services/storage/public/mojom/cache_storage_control.mojom.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/mojom/cache_storage/cache_storage.mojom-mojolpm.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"
#include "ui/aura/env.h"
#include "ui/events/devices/device_data_manager.h"
#include "url/gurl.h"

namespace content {

namespace {

constexpr const char* kCmdline[] = {"cache_storage_mojolpm_fuzzer", nullptr};
constexpr char kTestUrl[] = "https://example.test/";

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

class CacheStorageTestcase
    : public ::mojolpm::Testcase<
          content::fuzzing::cache_storage::proto::Testcase,
          content::fuzzing::cache_storage::proto::Action> {
 public:
  using ProtoTestcase = content::fuzzing::cache_storage::proto::Testcase;
  using ProtoAction = content::fuzzing::cache_storage::proto::Action;

  explicit CacheStorageTestcase(const ProtoTestcase& testcase);

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
  TestWebContentsFactory web_contents_factory_;
  raw_ptr<WebContents> web_contents_ = nullptr;
  mojo::Remote<blink::mojom::CacheStorage> cache_storage_remote_;
  mojo::PendingReceiver<blink::mojom::CacheStorage>
      cache_storage_receiver_;
};

CacheStorageTestcase::CacheStorageTestcase(const ProtoTestcase& testcase)
    : Testcase<ProtoTestcase, ProtoAction>(testcase) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

void CacheStorageTestcase::SetUp(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  cache_storage_receiver_ =
      cache_storage_remote_.BindNewPipeAndPassReceiver();
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&CacheStorageTestcase::SetUpOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void CacheStorageTestcase::SetUpOnUIThread(
    base::OnceClosure done_closure) {
  aura_env_ = aura::Env::CreateInstance();
  ui::DeviceDataManager::CreateInstance();
  browser_context_ = std::make_unique<TestBrowserContext>();
  web_contents_ =
      web_contents_factory_.CreateWebContents(browser_context_.get());
  static_cast<TestWebContents*>(web_contents_)->NavigateAndCommit(
      GURL(kTestUrl));
  static_cast<TestRenderFrameHost*>(web_contents_->GetPrimaryMainFrame())
      ->InitializeRenderFrameIfNeeded();

  auto* render_frame_host = static_cast<RenderFrameHostImpl*>(
      web_contents_->GetPrimaryMainFrame());
  auto* storage_partition = static_cast<StoragePartitionImpl*>(
      browser_context_->GetDefaultStoragePartition());
  storage_partition->GetCacheStorageControl()->AddReceiver(
      network::CrossOriginEmbedderPolicy(), {}, network::DocumentIsolationPolicy(),
      {}, storage::BucketLocator::ForDefaultBucket(
              render_frame_host->GetStorageKey()),
      storage::mojom::CacheStorageOwner::kCacheAPI,
      std::move(cache_storage_receiver_));

  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CacheStorageTestcase::SetUpOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void CacheStorageTestcase::SetUpOnFuzzerThread(
    base::OnceClosure done_closure) {
  ::mojolpm::GetContext()->StartTestcase();
  ::mojolpm::GetContext()->AddInstance(0, std::move(cache_storage_remote_));
  std::move(done_closure).Run();
}

void CacheStorageTestcase::TearDown(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ::mojolpm::GetContext()->EndTestcase();
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&CacheStorageTestcase::TearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void CacheStorageTestcase::TearDownOnUIThread(
    base::OnceClosure done_closure) {
  web_contents_factory_.DestroyWebContents(web_contents_);
  web_contents_ = nullptr;
  browser_context_.reset();
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CacheStorageTestcase::TearDownOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void CacheStorageTestcase::TearDownOnFuzzerThread(
    base::OnceClosure done_closure) {
  std::move(done_closure).Run();
}

void CacheStorageTestcase::RunAction(const ProtoAction& action,
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
                    FROM_HERE, base::DoNothing(), std::move(done_closure));
              },
              std::move(done_closure)));
      return;
    case ProtoAction::kCacheStorageRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.cache_storage_remote_action());
      break;
    case ProtoAction::kCacheStorageCacheRemoteAction:
      ::mojolpm::HandleAssociatedRemoteAction(
          action.cache_storage_cache_remote_action());
      break;
    case ProtoAction::ACTION_NOT_SET:
      break;
  }

  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

}  // namespace content

DEFINE_BINARY_PROTO_FUZZER(
    const content::fuzzing::cache_storage::proto::Testcase& proto_testcase) {
  if (!proto_testcase.actions_size() || !proto_testcase.sequences_size() ||
      !proto_testcase.sequence_indexes_size()) {
    return;
  }

  content::GetEnvironment();
  content::CacheStorageTestcase testcase(proto_testcase);
  base::RunLoop main_run_loop;
  content::GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &::mojolpm::RunTestcase<content::CacheStorageTestcase>,
          base::Unretained(&testcase), content::GetFuzzerTaskRunner(),
          main_run_loop.QuitClosure()));
  main_run_loop.Run();
}
