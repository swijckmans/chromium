// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "content/browser/blob_storage/chrome_blob_storage_context.h"  // nogncheck
#include "content/browser/file_system_access/file_system_access.pb.h"  // nogncheck
#include "content/browser/file_system_access/file_system_access_manager_impl.h"  // nogncheck
#include "content/browser/file_system_access/fixed_file_system_access_permission_grant.h"  // nogncheck
#include "content/browser/file_system_access/mock_file_system_access_permission_context.h"  // nogncheck
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/test/test_browser_context.h"
#include "content/public/test/test_web_contents_factory.h"
#include "content/test/fuzzer/file_system_access_manager_mojolpm_fuzzer.pb.h"
#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "content/test/test_web_contents.h"
#include "components/services/storage/public/mojom/file_system_access_context.mojom.h"  // nogncheck
#include "mojo/public/tools/fuzzers/mojolpm.h"
#include "storage/browser/file_system/file_system_context.h"
#include "storage/browser/quota/quota_manager_proxy.h"
#include "storage/browser/test/mock_quota_manager.h"
#include "storage/browser/test/mock_quota_manager_proxy.h"
#include "storage/browser/test/mock_special_storage_policy.h"
#include "storage/browser/test/test_file_system_context.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_access_handle_host.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_data_transfer_token.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_directory_handle.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_handle.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_writer.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_manager.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_observer.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_observer_host.mojom-mojolpm.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_transfer_token.mojom-mojolpm.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"
#include "ui/aura/env.h"
#include "ui/events/devices/device_data_manager.h"
#include "url/gurl.h"

namespace content {

namespace {

constexpr const char* kCmdline[] = {
    "file_system_access_manager_mojolpm_fuzzer",
    nullptr,
};
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

class FileSystemAccessManagerTestcase
    : public ::mojolpm::Testcase<
          content::fuzzing::file_system_access_manager::proto::Testcase,
          content::fuzzing::file_system_access_manager::proto::Action> {
 public:
  using ProtoTestcase =
      content::fuzzing::file_system_access_manager::proto::Testcase;
  using ProtoAction =
      content::fuzzing::file_system_access_manager::proto::Action;

  explicit FileSystemAccessManagerTestcase(const ProtoTestcase& testcase);

  void SetUp(base::OnceClosure done_closure) override;
  void TearDown(base::OnceClosure done_closure) override;
  void RunAction(const ProtoAction& action,
                 base::OnceClosure done_closure) override;

 private:
  void SetUpOnIOThread(base::OnceClosure done_closure);
  void SetUpOnUIThread(base::OnceClosure done_closure);
  void SetUpOnFuzzerThread(base::OnceClosure done_closure);
  void TearDownOnUIThread(base::OnceClosure done_closure);
  void TearDownOnIOThread(base::OnceClosure done_closure);
  void TearDownOnFuzzerThread(base::OnceClosure done_closure);

  void SerializeHandle(
      const content::fuzzing::file_system_access_manager::proto::
          SerializeHandleAction& action);
  void DeserializeHandle(
      const content::fuzzing::file_system_access_manager::proto::
          DeserializeHandleAction& action);

  const GURL test_url_ = GURL(kTestUrl);
  const blink::StorageKey storage_key_ =
      blink::StorageKey::CreateFromStringForTesting(test_url_.spec());

  std::unique_ptr<aura::Env> aura_env_;
  std::unique_ptr<TestBrowserContext> browser_context_;
  TestWebContentsFactory web_contents_factory_;
  raw_ptr<WebContents> web_contents_ = nullptr;
  GlobalRenderFrameHostId frame_id_;
  FileSystemAccessManagerImpl::BindingContext binding_context_ = {
      storage_key_, test_url_, GlobalRenderFrameHostId()};

  base::ScopedTempDir temp_dir_;
  scoped_refptr<storage::MockSpecialStoragePolicy> special_storage_policy_ =
      base::MakeRefCounted<storage::MockSpecialStoragePolicy>();
  scoped_refptr<storage::MockQuotaManager> quota_manager_;
  scoped_refptr<storage::MockQuotaManagerProxy> quota_manager_proxy_;
  scoped_refptr<storage::FileSystemContext> file_system_context_;
  scoped_refptr<ChromeBlobStorageContext> blob_storage_context_;

  testing::NiceMock<MockFileSystemAccessPermissionContext>
      permission_context_;
  scoped_refptr<FixedFileSystemAccessPermissionGrant> allow_grant_ =
      base::MakeRefCounted<FixedFileSystemAccessPermissionGrant>(
          blink::mojom::PermissionStatus::GRANTED,
          PathInfo());
  scoped_refptr<FileSystemAccessManagerImpl> manager_;

  mojo::Remote<blink::mojom::FileSystemAccessManager> manager_remote_;
  mojo::Remote<storage::mojom::FileSystemAccessContext> context_remote_;
  mojo::PendingReceiver<blink::mojom::FileSystemAccessManager>
      manager_receiver_;
  mojo::PendingReceiver<storage::mojom::FileSystemAccessContext>
      context_receiver_;
  std::shared_ptr<std::map<uint32_t, std::vector<uint8_t>>>
      serialized_handle_bits_ =
          std::make_shared<std::map<uint32_t, std::vector<uint8_t>>>();
};

FileSystemAccessManagerTestcase::FileSystemAccessManagerTestcase(
    const ProtoTestcase& testcase)
    : Testcase<ProtoTestcase, ProtoAction>(testcase) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

void FileSystemAccessManagerTestcase::SetUp(base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  manager_receiver_ = manager_remote_.BindNewPipeAndPassReceiver();
  context_receiver_ = context_remote_.BindNewPipeAndPassReceiver();
  content::GetIOThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&FileSystemAccessManagerTestcase::SetUpOnIOThread,
                     base::Unretained(this), std::move(done_closure)));
}

void FileSystemAccessManagerTestcase::SetUpOnIOThread(
    base::OnceClosure done_closure) {
  CHECK(temp_dir_.CreateUniqueTempDir());
  quota_manager_ = base::MakeRefCounted<storage::MockQuotaManager>(
      false, temp_dir_.GetPath(), base::SingleThreadTaskRunner::GetCurrentDefault(),
      special_storage_policy_);
  quota_manager_proxy_ = base::MakeRefCounted<storage::MockQuotaManagerProxy>(
      quota_manager_.get(),
      base::SingleThreadTaskRunner::GetCurrentDefault().get());
  file_system_context_ = storage::CreateFileSystemContextForTesting(
      quota_manager_proxy_.get(), temp_dir_.GetPath());
  blob_storage_context_ = base::MakeRefCounted<ChromeBlobStorageContext>();
  blob_storage_context_->InitializeOnIOThread(
      temp_dir_.GetPath(), temp_dir_.GetPath(), nullptr);

  content::GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&FileSystemAccessManagerTestcase::SetUpOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void FileSystemAccessManagerTestcase::SetUpOnUIThread(
    base::OnceClosure done_closure) {
  using testing::_;
  using testing::Return;

  aura_env_ = aura::Env::CreateInstance();
  ui::DeviceDataManager::CreateInstance();

  ON_CALL(permission_context_, GetReadPermissionGrant(_, _, _, _))
      .WillByDefault(Return(allow_grant_));
  ON_CALL(permission_context_, GetWritePermissionGrant(_, _, _, _))
      .WillByDefault(Return(allow_grant_));
  ON_CALL(permission_context_, IsFileTypeDangerous_(_))
      .WillByDefault(Return(false));
  ON_CALL(permission_context_, CanShowFilePicker(_))
      .WillByDefault(Return(base::ok()));
  ON_CALL(permission_context_, CanObtainReadPermission(_))
      .WillByDefault(Return(true));
  ON_CALL(permission_context_, CanObtainWritePermission(_))
      .WillByDefault(Return(true));
  ON_CALL(permission_context_, GetLastPickedDirectory(_, _))
      .WillByDefault(Return(PathInfo()));
  ON_CALL(permission_context_, GetWellKnownDirectoryPath(_, _))
      .WillByDefault(Return(base::FilePath()));
  ON_CALL(permission_context_, GetPickerTitle(_))
      .WillByDefault(Return(std::u16string()));
  ON_CALL(permission_context_, ConfirmSensitiveEntryAccess_(_, _, _, _, _, _))
      .WillByDefault([](const url::Origin&, const PathInfo&,
                        FileSystemAccessPermissionContext::HandleType,
                        FileSystemAccessPermissionContext::UserAction,
                        GlobalRenderFrameHostId,
                        base::OnceCallback<void(
                            FileSystemAccessPermissionContext::
                                SensitiveEntryResult)>& callback) {
        std::move(callback).Run(
            FileSystemAccessPermissionContext::SensitiveEntryResult::kAllowed);
      });
  ON_CALL(permission_context_, PerformAfterWriteChecks_(_, _, _))
      .WillByDefault([](FileSystemAccessWriteItem*,
                        GlobalRenderFrameHostId,
                        base::OnceCallback<void(
                            FileSystemAccessPermissionContext::
                                AfterWriteCheckResult)>& callback) {
        std::move(callback).Run(
            FileSystemAccessPermissionContext::AfterWriteCheckResult::kAllow);
      });

  browser_context_ = std::make_unique<TestBrowserContext>();
  web_contents_ = web_contents_factory_.CreateWebContents(browser_context_.get());
  static_cast<TestWebContents*>(web_contents_)->NavigateAndCommit(test_url_);
  frame_id_ = web_contents_->GetPrimaryMainFrame()->GetGlobalId();
  binding_context_ = {storage_key_, test_url_, frame_id_};

  manager_ = base::MakeRefCounted<FileSystemAccessManagerImpl>(
      file_system_context_, blob_storage_context_, &permission_context_, false);
  manager_->BindReceiver(binding_context_, std::move(manager_receiver_));
  manager_->BindInternalsReceiver(std::move(context_receiver_));

  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&FileSystemAccessManagerTestcase::SetUpOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void FileSystemAccessManagerTestcase::SetUpOnFuzzerThread(
    base::OnceClosure done_closure) {
  ::mojolpm::GetContext()->StartTestcase();
  ::mojolpm::GetContext()->AddInstance(0, std::move(manager_remote_));
  ::mojolpm::GetContext()->AddInstance(0, std::move(context_remote_));
  std::move(done_closure).Run();
}

void FileSystemAccessManagerTestcase::TearDown(
    base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  content::GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&FileSystemAccessManagerTestcase::TearDownOnUIThread,
                     base::Unretained(this), std::move(done_closure)));
}

void FileSystemAccessManagerTestcase::TearDownOnUIThread(
    base::OnceClosure done_closure) {
  manager_.reset();
  web_contents_factory_.DestroyWebContents(web_contents_);
  web_contents_ = nullptr;
  browser_context_.reset();
  content::GetIOThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&FileSystemAccessManagerTestcase::TearDownOnIOThread,
                     base::Unretained(this), std::move(done_closure)));
}

void FileSystemAccessManagerTestcase::TearDownOnIOThread(
    base::OnceClosure done_closure) {
  blob_storage_context_.reset();
  file_system_context_.reset();
  quota_manager_proxy_.reset();
  quota_manager_.reset();
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&FileSystemAccessManagerTestcase::TearDownOnFuzzerThread,
                     base::Unretained(this), std::move(done_closure)));
}

void FileSystemAccessManagerTestcase::TearDownOnFuzzerThread(
    base::OnceClosure done_closure) {
  ::mojolpm::GetContext()->EndTestcase();
  std::move(done_closure).Run();
}

void FileSystemAccessManagerTestcase::SerializeHandle(
    const content::fuzzing::file_system_access_manager::proto::
        SerializeHandleAction& action) {
  auto token =
      ::mojolpm::GetContext()->GetAndRemoveInstance<
          mojo::Remote<blink::mojom::FileSystemAccessTransferToken>>(
          action.token_id());
  auto* context =
      ::mojolpm::GetContext()->GetInstance<
          mojo::Remote<storage::mojom::FileSystemAccessContext>>(
          action.context_id());
  if (!token || !context) {
    return;
  }
  const uint32_t bits_id = action.bits_id();
  auto serialized_handle_bits = serialized_handle_bits_;
  context->get()->SerializeHandle(
      token->Unbind(),
      base::BindOnce(
          [](scoped_refptr<base::SequencedTaskRunner> fuzzer_task_runner,
             std::shared_ptr<std::map<uint32_t, std::vector<uint8_t>>>
                 serialized_bits,
             uint32_t bits_id, const std::vector<uint8_t>& bits) {
            fuzzer_task_runner->PostTask(
                FROM_HERE,
                base::BindOnce(
                    [](std::shared_ptr<std::map<uint32_t, std::vector<uint8_t>>>
                           serialized_bits,
                       uint32_t bits_id, std::vector<uint8_t> bits) {
                      (*serialized_bits)[bits_id] = std::move(bits);
                    },
                    std::move(serialized_bits), bits_id, bits));
          },
          GetFuzzerTaskRunner(), std::move(serialized_handle_bits), bits_id));
}

void FileSystemAccessManagerTestcase::DeserializeHandle(
    const content::fuzzing::file_system_access_manager::proto::
        DeserializeHandleAction& action) {
  auto* context =
      ::mojolpm::GetContext()->GetInstance<
          mojo::Remote<storage::mojom::FileSystemAccessContext>>(
          action.context_id());
  if (!context) {
    return;
  }
  std::vector<uint8_t> bits;
  if (action.has_bits()) {
    bits.assign(action.bits().begin(), action.bits().end());
  } else if (action.has_bits_id()) {
    auto it = serialized_handle_bits_->find(action.bits_id());
    if (it == serialized_handle_bits_->end()) {
      return;
    }
    bits = it->second;
  } else {
    return;
  }
  if (bits.empty()) {
    // FileSystemAccessContext is browser-internal and never receives renderer
    // bytes, so malformed raw bits are a harness-only concern.
    return;
  }
  FileSystemAccessHandleData data;
  if (!data.ParseFromString(base::as_string_view(bits)) ||
      data.data_case() == FileSystemAccessHandleData::DATA_NOT_SET) {
    return;
  }
  mojo::Remote<blink::mojom::FileSystemAccessTransferToken> token;
  auto receiver = token.BindNewPipeAndPassReceiver();
  context->get()->DeserializeHandle(storage_key_, std::move(bits),
                                    std::move(receiver));
  ::mojolpm::GetContext()->AddInstance(action.token_id(), std::move(token));
}

void FileSystemAccessManagerTestcase::RunAction(
    const ProtoAction& action,
    base::OnceClosure done_closure) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  switch (action.action_case()) {
    case ProtoAction::kRunUntilIdle:
      content::GetUIThreadTaskRunner({})->PostTaskAndReply(
          FROM_HERE, base::DoNothing(), std::move(done_closure));
      return;
    case ProtoAction::kFileSystemAccessManagerRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_manager_remote_action());
      break;
    case ProtoAction::kFileSystemAccessDirectoryHandleRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_directory_handle_remote_action());
      break;
    case ProtoAction::kFileSystemAccessFileHandleRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_file_handle_remote_action());
      break;
    case ProtoAction::kFileSystemAccessFileWriterRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_file_writer_remote_action());
      break;
    case ProtoAction::kFileSystemAccessAccessHandleHostRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_access_handle_host_remote_action());
      break;
    case ProtoAction::kFileSystemAccessTransferTokenRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_transfer_token_remote_action());
      break;
    case ProtoAction::kFileSystemAccessDataTransferTokenRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_data_transfer_token_remote_action());
      break;
    case ProtoAction::kFileSystemAccessObserverHostRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_observer_host_remote_action());
      break;
    case ProtoAction::kFileSystemAccessObserverRemoteAction:
      ::mojolpm::HandleRemoteAction(
          action.file_system_access_observer_remote_action());
      break;
    case ProtoAction::kSerializeHandle:
      SerializeHandle(action.serialize_handle());
      break;
    case ProtoAction::kDeserializeHandle:
      DeserializeHandle(action.deserialize_handle());
      break;
    case ProtoAction::ACTION_NOT_SET:
      break;
  }

  GetFuzzerTaskRunner()->PostTask(FROM_HERE, std::move(done_closure));
}

}  // namespace content

DEFINE_BINARY_PROTO_FUZZER(
    const content::fuzzing::file_system_access_manager::proto::Testcase&
        proto_testcase) {
  if (!proto_testcase.actions_size() || !proto_testcase.sequences_size() ||
      !proto_testcase.sequence_indexes_size()) {
    return;
  }

  content::GetEnvironment();
  content::FileSystemAccessManagerTestcase testcase(proto_testcase);
  base::RunLoop main_run_loop;
  content::GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&::mojolpm::RunTestcase<
                         content::FileSystemAccessManagerTestcase>,
                     base::Unretained(&testcase),
                     content::GetFuzzerTaskRunner(),
                     main_run_loop.QuitClosure()));
  main_run_loop.Run();
}
