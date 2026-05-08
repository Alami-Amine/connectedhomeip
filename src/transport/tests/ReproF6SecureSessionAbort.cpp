/*
 *    Deterministic reproducer for F-6: SecureSessionTable::CreateNewSecureSession
 *    aborts via VerifyOrDieWithMsg(false, ...) when the pool is full and every
 *    candidate session is pinned by a SessionHandle strong reference.
 *
 *    See SecureSessionTable.cpp:189-225 and upstream issue #19495.
 *
 *    Built as a libfuzzer target so we can reuse the existing chip_fuzz_target
 *    pipeline; the input is ignored — first call triggers abort().
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include <inet/IPAddress.h>
#include <lib/core/CHIPConfig.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/ScopedNodeId.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <messaging/ReliableMessageProtocolConfig.h>
#include <transport/SecureSession.h>
#include <transport/SecureSessionTable.h>
#include <transport/raw/PeerAddress.h>

namespace {

using namespace chip;
using namespace chip::Transport;

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

ReliableMessageProtocolConfig DefaultMrp()
{
    return ReliableMessageProtocolConfig(System::Clock::Milliseconds32(0x100),
                                          System::Clock::Milliseconds32(0x80),
                                          System::Clock::Milliseconds16(32));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * /*data*/, size_t /*size*/)
{
    (void) EnsureInitialized();

    SecureSessionTable table;
    table.Init();

    std::vector<std::unique_ptr<SessionHandle>> handles;
    handles.reserve(CHIP_CONFIG_SECURE_SESSION_POOL_SIZE);

    // Fill the pool to capacity, all CASE, all on fabric 1, each with a unique
    // operational NodeId. Hold every SessionHandle so each slot is pinned by
    // a strong ref.
    for (size_t i = 0; i < CHIP_CONFIG_SECURE_SESSION_POOL_SIZE; ++i)
    {
        const NodeId peer  = static_cast<NodeId>(0x0000000000000001ULL + i);
        const NodeId local = static_cast<NodeId>(0x0000000000010000ULL + i);
        ScopedNodeId hint(peer, /*fabric=*/1);

        auto opt = table.CreateNewSecureSession(SecureSession::Type::kCASE, hint);
        VerifyOrDie(opt.HasValue());

        auto * ss = opt.Value()->AsSecureSession();
        ss->Activate(ScopedNodeId(local, 1), ScopedNodeId(peer, 1), CATValues(),
                     static_cast<uint16_t>(0x1000 + i), DefaultMrp());

        handles.push_back(std::make_unique<SessionHandle>(std::move(opt.Value())));
    }

    // Pool is full. All slots pinned. The next CreateNewSecureSession enters the
    // eviction loop; every candidate has a SessionHandle, so MarkForEviction
    // never reduces the pool count, and the function falls through to
    // VerifyOrDieWithMsg(false, ...). That is an unconditional abort().
    ScopedNodeId hint(static_cast<NodeId>(0x42), /*fabric=*/1);
    auto opt = table.CreateNewSecureSession(SecureSession::Type::kCASE, hint);
    (void) opt; // unreachable

    return 0;
}
