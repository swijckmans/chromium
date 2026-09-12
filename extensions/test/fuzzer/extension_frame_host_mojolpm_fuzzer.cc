// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/test_render_frame_host.h"
#include "content/test/test_web_contents.h"
#include "extensions/browser/extension_frame_host.h"
#include "extensions/browser/extension_web_contents_observer.h"
#include "extensions/common/mojom/frame.mojom-mojolpm.h"
#include "extensions/common/mojom/frame.mojom.h"
#include "extensions/test/fuzzer/extension_frame_host_mojolpm_fuzzer.pb.h"
#include "extensions/test/fuzzer/extension_mojolpm_fuzzer_support.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"

namespace {

class FuzzerExtensionWebContentsObserver
    : public extensions::ExtensionWebContentsObserver {
 public:
  explicit FuzzerExtensionWebContentsObserver(
      content::WebContents* web_contents)
      : ExtensionWebContentsObserver(web_contents) {}
};

}  // namespace

using extensions::mojolpm::GetEnvironment;
using extensions::mojolpm::GetFuzzerTaskRunner;

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
  extensions::mojolpm::ExtensionFuzzerWorld world_{&test_adapter_};
  raw_ptr<content::TestRenderFrameHost> render_frame_host_ = nullptr;
  std::unique_ptr<extensions::ExtensionFrameHost> extension_frame_host_;
  std::unique_ptr<FuzzerExtensionWebContentsObserver> observer_;
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
  world_.SetUp();
  render_frame_host_ = world_.main_rfh();
  extension_frame_host_ =
      std::make_unique<extensions::ExtensionFrameHost>(world_.web_contents());
  observer_ = std::make_unique<FuzzerExtensionWebContentsObserver>(
      world_.web_contents());
  GetEnvironment().SetFuzzerObserver(observer_.get());

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
  GetEnvironment().SetFuzzerObserver(nullptr);
  observer_.reset();
  world_.TearDown();
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
          FROM_HERE, base::BindOnce([]() {
            base::RunLoop run_loop(base::RunLoop::Type::kNestableTasksAllowed);
            run_loop.RunUntilIdle();
          }),
          std::move(done_closure));
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
