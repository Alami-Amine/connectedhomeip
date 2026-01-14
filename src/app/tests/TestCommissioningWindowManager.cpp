/*
 *
 *    Copyright (c) 2021-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <app/TestEventTriggerDelegate.h>
#include <app/reporting/ReportSchedulerImpl.h>
#include <app/server/CommissioningWindowManager.h>
#include <app/server/Server.h>
#include <crypto/RandUtils.h>
#include <data-model-providers/codegen/CodegenDataModelProvider.h>
#include <lib/dnssd/Advertiser.h>
#include <lib/support/Span.h>
#include <messaging/tests/echo/common.h>
#include <platform/CHIPDeviceLayer.h>
#include <platform/CommissionableDataProvider.h>
#include <platform/ConfigurationManager.h>
#include <platform/DefaultTimerDelegate.h>
#include <platform/PlatformManager.h>
#include <platform/TestOnlyCommissionableDataProvider.h>
#include <protocols/secure_channel/PASESession.h>

#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/tests/ExtraPwTestMacros.h>
#include <pw_unit_test/framework.h>

#include <lib/support/UnitTestUtils.h>
#include <messaging/tests/MessagingContext.h>
#include <system/RAIIMockClock.h>

#include <lib/support/CHIPFaultInjection.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-const-variable"
#pragma clang diagnostic ignored "-Wunused-function"

using namespace chip;
using namespace chip::Crypto;
using namespace chip::Messaging;
using namespace System::Clock::Literals;

using chip::CommissioningWindowAdvertisement;
using chip::CommissioningWindowManager;
using chip::Server;

namespace {

// Test Set #01 of Spake2p Parameters (PIN Code, Iteration Count, Salt, and matching Verifier):
constexpr uint32_t sTestSpake2p01_PinCode        = 20202021;
constexpr uint32_t sTestSpake2p01_IterationCount = 1000;
constexpr uint8_t sTestSpake2p01_Salt[]          = { 0x53, 0x50, 0x41, 0x4B, 0x45, 0x32, 0x50, 0x20,
                                                     0x4B, 0x65, 0x79, 0x20, 0x53, 0x61, 0x6C, 0x74 };
Spake2pVerifier sTestSpake2p01_PASEVerifier = { .mW0 = {
    0xB9, 0x61, 0x70, 0xAA, 0xE8, 0x03, 0x34, 0x68, 0x84, 0x72, 0x4F, 0xE9, 0xA3, 0xB2, 0x87, 0xC3,
    0x03, 0x30, 0xC2, 0xA6, 0x60, 0x37, 0x5D, 0x17, 0xBB, 0x20, 0x5A, 0x8C, 0xF1, 0xAE, 0xCB, 0x35,
},
    .mL  = {
    0x04, 0x57, 0xF8, 0xAB, 0x79, 0xEE, 0x25, 0x3A, 0xB6, 0xA8, 0xE4, 0x6B, 0xB0, 0x9E, 0x54, 0x3A,
    0xE4, 0x22, 0x73, 0x6D, 0xE5, 0x01, 0xE3, 0xDB, 0x37, 0xD4, 0x41, 0xFE, 0x34, 0x49, 0x20, 0xD0,
    0x95, 0x48, 0xE4, 0xC1, 0x82, 0x40, 0x63, 0x0C, 0x4F, 0xF4, 0x91, 0x3C, 0x53, 0x51, 0x38, 0x39,
    0xB7, 0xC0, 0x7F, 0xCC, 0x06, 0x27, 0xA1, 0xB8, 0x57, 0x3A, 0x14, 0x9F, 0xCD, 0x1F, 0xA4, 0x66,
    0xCF
} };

bool sAdminFabricIndexDirty = false;
bool sAdminVendorIdDirty    = false;
bool sWindowStatusDirty     = false;

bool sSimulateFailedSessionEstablishmentTaskCalled          = false;
bool sCheckCommissioningWindowManagerWindowClosedTaskCalled = false;

void ResetDirtyFlags()
{
    sAdminFabricIndexDirty = false;
    sAdminVendorIdDirty    = false;
    sWindowStatusDirty     = false;
}

class TestCommissioningWindowManagerDataModelProvider : public chip::app::CodegenDataModelProvider
{
public:
    TestCommissioningWindowManagerDataModelProvider()  = default;
    ~TestCommissioningWindowManagerDataModelProvider() = default;

    void Temporary_ReportAttributeChanged(const chip::app::AttributePathParams & path) override
    {
        using namespace chip::app::Clusters;
        using namespace chip::app::Clusters::AdministratorCommissioning::Attributes;
        if (path.mEndpointId != chip::kRootEndpointId || path.mClusterId != AdministratorCommissioning::Id)
        {
            return;
        }

        switch (path.mAttributeId)
        {
        case WindowStatus::Id:
            sWindowStatusDirty = true;
            break;
        case AdminVendorId::Id:
            sAdminVendorIdDirty = true;
            break;
        case AdminFabricIndex::Id:
            sAdminFabricIndexDirty = true;
            break;
        default:
            break;
        }
    }
};

chip::app::DataModel::Provider * TestDataModelProviderInstance(chip::PersistentStorageDelegate * delegate)
{
    static TestCommissioningWindowManagerDataModelProvider gTestModel;

    if (delegate != nullptr)
    {
        gTestModel.SetPersistentStorageDelegate(delegate);
    }

    return &gTestModel;
}

} // namespace
namespace {

void TearDownTask(intptr_t context)
{
    chip::Server::GetInstance().Shutdown();
}

static void StopEventLoop(intptr_t context)
{
    EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().StopEventLoopTask());
}

class TestSecurePairingDelegate : public SessionEstablishmentDelegate
{
public:
    void OnSessionEstablishmentError(CHIP_ERROR error) override { mNumPairingErrors++; }

    void OnSessionEstablished(const SessionHandle & session) override { mNumPairingComplete++; }

    uint32_t mNumPairingErrors   = 0;
    uint32_t mNumPairingComplete = 0;
};

class MockAppDelegate : public AppDelegate
{
public:
    // void OnCommissioningWindowOpened(
    //     chip::FabricIndex fabricIndex, chip::VendorId vendorId,
    //     chip::app::Clusters::AdministratorCommissioning::CommissioningWindowAdvertisement advertisementMode) override
    // {
    //     mOnCommissioningWindowOpenedCalled = true;
    //     mFabricIndex                       = fabricIndex;
    //     mVendorId                          = vendorId;
    //     mAdvertisementMode                 = advertisementMode;
    // }
    // bool mOnCommissioningWindowOpenedCalled = false;
    // chip::FabricIndex mFabricIndex;
    // chip::VendorId mVendorId;
    // chip::app::Clusters::AdministratorCommissioning::CommissioningWindowAdvertisement mAdvertisementMode;

    void OnCommissioningSessionEstablishmentError(CHIP_ERROR error) override
    {
        mNumSessionEstablishmentErrors++;
        mError = error;
    }
    void OnCommissioningWindowClosed() override {}
    uint8_t mNumSessionEstablishmentErrors = 0;
    CHIP_ERROR mError;
};

class TestCommissioningWindowManager : public chip::Testing::LoopbackMessagingContext
{
public:
    static void SetUpTestSuite()
    {
        LoopbackMessagingContext::SetUpTestSuite();

        ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
        ASSERT_EQ(chip::DeviceLayer::PlatformMgr().InitChipStack(), CHIP_NO_ERROR);

        static chip::DeviceLayer::TestOnlyCommissionableDataProvider commissionableDataProvider;
        chip::DeviceLayer::SetCommissionableDataProvider(&commissionableDataProvider);

        static chip::CommonCaseDeviceServerInitParams initParams;
        // Report scheduler and timer delegate instance
        static chip::app::DefaultTimerDelegate sTimerDelegate;
        static chip::app::reporting::ReportSchedulerImpl sReportScheduler(&sTimerDelegate);
        initParams.reportScheduler = &sReportScheduler;
        static chip::SimpleTestEventTriggerDelegate sSimpleTestEventTriggerDelegate;
        initParams.testEventTriggerDelegate = &sSimpleTestEventTriggerDelegate;
        (void) initParams.InitializeStaticResourcesBeforeServerInit();
        initParams.dataModelProvider = TestDataModelProviderInstance(initParams.persistentStorageDelegate);
        // Use whatever server port the kernel decides to give us.
        initParams.operationalServicePort = 0;

        ASSERT_EQ(chip::Server::GetInstance().Init(initParams), CHIP_NO_ERROR);

        Server::GetInstance().GetCommissioningWindowManager().CloseCommissioningWindow();
    }
    static void TearDownTestSuite()
    {

        // TODO: The platform memory was intentionally left not deinitialized so that minimal mdns can destruct
        EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(TearDownTask, 0));
        EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(StopEventLoop));
        chip::DeviceLayer::PlatformMgr().RunEventLoop();

        chip::DeviceLayer::PlatformMgr().Shutdown();

        auto & mdnsAdvertiser = chip::Dnssd::ServiceAdvertiser::Instance();
        RETURN_SAFELY_IGNORED mdnsAdvertiser.RemoveServices();
        mdnsAdvertiser.Shutdown();

        LoopbackMessagingContext::TearDownTestSuite();

        // Server shutdown will be called in TearDownTask

        // TODO: At this point UDP endpoits still seem leaked and the sanitizer
        // builds will attempt a memory free. As a result, we keep Memory initialized
        // so that the global UDPManager can still be destructed without a coredump.
        //
        // This is likely either a missing shutdown or an actual UDP endpoint leak
        // which I have not been able to track down yet.
        //
        // chip::Platform::MemoryShutdown();
    }

    void SetUp() override
    {
        ConfigInitializeNodes(false);
        chip::Testing::LoopbackMessagingContext::SetUp();
        sSimulateFailedSessionEstablishmentTaskCalled          = false;
        sCheckCommissioningWindowManagerWindowClosedTaskCalled = false;
    }

    void EstablishPASEHandshake(SessionManager & sessionManager, PASESession & pairingCommissioner,
                                TestSecurePairingDelegate & delegateCommissioner);

    void ServiceEvents();
};

void TestCommissioningWindowManager::ServiceEvents()
{
    DrainAndServiceIO();

    EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(
        [](intptr_t) -> void { EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().StopEventLoopTask()); }, (intptr_t) nullptr));
    chip::DeviceLayer::PlatformMgr().RunEventLoop();
}

void TestCommissioningWindowManager::EstablishPASEHandshake(SessionManager & sessionManager, PASESession & pairingCommissioner,
                                                            TestSecurePairingDelegate & delegateCommissioner)
{

    auto & loopback            = GetLoopback();
    loopback.mSentMessageCount = 0;

    ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::PBKDFParamRequest,
                                                                            &Server::GetInstance().GetCommissioningWindowManager()),
              CHIP_NO_ERROR);

    DrainAndServiceIO();

    EXPECT_EQ(pairingCommissioner.Pair(sessionManager, sTestSpake2p01_PinCode, Optional<ReliableMessageProtocolConfig>::Missing(),
                                       contextCommissioner, &delegateCommissioner),
              CHIP_NO_ERROR);
    DrainAndServiceIO();

    // EXPECT_EQ(delegateCommissioner.mNumPairingErrors, 0u);
    // EXPECT_EQ(delegateCommissioner.mNumPairingComplete, 1u);
}

class TemporarySessionManager
{
public:
    TemporarySessionManager(TestCommissioningWindowManager & ctx) : mCtx(ctx)
    {
        EXPECT_EQ(CHIP_NO_ERROR,
                  mSessionManager.Init(&ctx.GetSystemLayer(), &ctx.GetTransportMgr(), &ctx.GetMessageCounterManager(), &mStorage,
                                       &ctx.GetFabricTable(), ctx.GetSessionKeystore()));
        // The setup here is really weird: we are using one session manager for
        // the actual messages we send (the PASE handshake, so the
        // unauthenticated sessions) and a different one for allocating the PASE
        // sessions.  Since our Init() set us up as the thing to handle messages
        // on the transport manager, undo that.
        mCtx.GetTransportMgr().SetSessionManager(&mCtx.GetSecureSessionManager());
    }

    ~TemporarySessionManager()
    {
        mSessionManager.Shutdown();
        // Reset the session manager on the transport again, just in case
        // shutdown messed with it.
        mCtx.GetTransportMgr().SetSessionManager(&mCtx.GetSecureSessionManager());
    }

    operator SessionManager &() { return mSessionManager; }

    TestCommissioningWindowManager & mCtx;

private:
    TestPersistentStorageDelegate mStorage;
    SessionManager mSessionManager;
};

TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerBasicWindowOpenClose)
{
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();

    EXPECT_EQ(commissionMgr.OpenBasicCommissioningWindow(commissionMgr.MaxCommissioningTimeout(),
                                                         CommissioningWindowAdvertisement::kDnssdOnly),
              CHIP_NO_ERROR);
    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);
    EXPECT_TRUE(commissionMgr.GetOpenerFabricIndex().IsNull());
    EXPECT_TRUE(commissionMgr.GetOpenerVendorId().IsNull());
    EXPECT_FALSE(chip::DeviceLayer::ConnectivityMgr().IsBLEAdvertisingEnabled());
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    commissionMgr.CloseCommissioningWindow();
    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    ChipLogError(AppServer, "AMINE: CheckCommissioningWindowManagerBasicWindowOpenCloseTask done");
}

// TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerBasicWindowOpenClose)
// {

//     EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(CheckCommissioningWindowManagerBasicWindowOpenCloseTask));
//     EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(StopEventLoop));
//     chip::DeviceLayer::PlatformMgr().RunEventLoop();
// }

TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerBasicWindowOpenCloseFromCluster)
{
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    constexpr auto fabricIndex                 = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId                    = static_cast<chip::VendorId>(0xFFF3);
    EXPECT_EQ(commissionMgr.OpenBasicCommissioningWindowForAdministratorCommissioningCluster(
                  commissionMgr.MaxCommissioningTimeout(), fabricIndex, vendorId),
              CHIP_NO_ERROR);
    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kBasicWindowOpen);
    EXPECT_FALSE(commissionMgr.GetOpenerFabricIndex().IsNull());
    EXPECT_EQ(commissionMgr.GetOpenerFabricIndex().Value(), fabricIndex);
    EXPECT_FALSE(commissionMgr.GetOpenerVendorId().IsNull());
    EXPECT_EQ(commissionMgr.GetOpenerVendorId().Value(), vendorId);
    EXPECT_FALSE(chip::DeviceLayer::ConnectivityMgr().IsBLEAdvertisingEnabled());
    EXPECT_TRUE(sWindowStatusDirty);
    EXPECT_TRUE(sAdminFabricIndexDirty);
    EXPECT_TRUE(sAdminVendorIdDirty);

    ResetDirtyFlags();
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    commissionMgr.CloseCommissioningWindow();
    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_TRUE(commissionMgr.GetOpenerFabricIndex().IsNull());
    EXPECT_TRUE(commissionMgr.GetOpenerVendorId().IsNull());
    EXPECT_TRUE(sWindowStatusDirty);
    EXPECT_TRUE(sAdminFabricIndexDirty);
    EXPECT_TRUE(sAdminVendorIdDirty);

    ResetDirtyFlags();

    ChipLogError(AppServer, "AMINE: CheckCommissioningWindowManagerBasicWindowOpenCloseFromClusterTask done");
}

// TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerBasicWindowOpenCloseFromCluster)
// {
//     EXPECT_SUCCESS(
//         chip::DeviceLayer::PlatformMgr().ScheduleWork(CheckCommissioningWindowManagerBasicWindowOpenCloseFromClusterTask));
//     EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(StopEventLoop));
//     chip::DeviceLayer::PlatformMgr().RunEventLoop();
// }

void CheckCommissioningWindowManagerWindowClosedTask(chip::System::Layer *, void *)
{
    ChipLogError(AppServer, "AMINE: CheckCommissioningWindowManagerWindowClosedTask called");
    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    sCheckCommissioningWindowManagerWindowClosedTaskCalled = true;
}

TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerWindowTimeout)
{
    System::Clock::Internal::RAIIMockClock clock;

    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    constexpr auto kTimeoutSeconds             = chip::System::Clock::Seconds32(1);
    constexpr uint16_t kTimeoutMs              = 1000;
    constexpr unsigned kSleepPadding           = 100;
    commissionMgr.OverrideMinCommissioningTimeout(kTimeoutSeconds);
    EXPECT_EQ(commissionMgr.OpenBasicCommissioningWindow(kTimeoutSeconds, CommissioningWindowAdvertisement::kDnssdOnly),
              CHIP_NO_ERROR);
    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);
    EXPECT_FALSE(chip::DeviceLayer::ConnectivityMgr().IsBLEAdvertisingEnabled());
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    EXPECT_SUCCESS(chip::DeviceLayer::SystemLayer().StartTimer(chip::System::Clock::Milliseconds32(kTimeoutMs + kSleepPadding),
                                                               CheckCommissioningWindowManagerWindowClosedTask, nullptr));

    clock.AdvanceMonotonic(chip::System::Clock::Milliseconds64(kTimeoutMs + kSleepPadding));
    ServiceEvents();

    EXPECT_TRUE(sCheckCommissioningWindowManagerWindowClosedTaskCalled);

    // TODO: remove all these Logs
    ChipLogError(AppServer, "AMINE: TestCheckCommissioningWindowManagerWindowTimeout done");
}

void SimulateFailedSessionEstablishmentTask(chip::System::Layer *, void *)
{
    ChipLogError(AppServer, "AMINE: SimulateFailedSessionEstablishmentTask called");

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    commissionMgr.OnSessionEstablishmentStarted();
    commissionMgr.OnSessionEstablishmentError(CHIP_ERROR_INTERNAL);
    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    sSimulateFailedSessionEstablishmentTaskCalled = true;
}

TEST_F(TestCommissioningWindowManager, CheckCommissioningWindowManagerWindowTimeoutWithSessionEstablishmentErrors)
{

    System::Clock::Internal::RAIIMockClock clock;

    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    CommissioningWindowManager & commissionMgr              = Server::GetInstance().GetCommissioningWindowManager();
    constexpr auto kTimeoutSeconds                          = chip::System::Clock::Seconds16(1);
    constexpr uint16_t kTimeoutMs                           = 1000;
    constexpr unsigned kSleepPadding                        = 100;
    constexpr uint16_t kFailedSessionEstablishmentTimeoutMs = kTimeoutMs / 4 * 3;

    MockAppDelegate delegateApp;
    commissionMgr.SetAppDelegate(&delegateApp);

    commissionMgr.OverrideMinCommissioningTimeout(kTimeoutSeconds);

    EXPECT_EQ(commissionMgr.OpenBasicCommissioningWindow(kTimeoutSeconds, CommissioningWindowAdvertisement::kDnssdOnly),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);

    EXPECT_FALSE(chip::DeviceLayer::ConnectivityMgr().IsBLEAdvertisingEnabled());
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    EXPECT_SUCCESS(chip::DeviceLayer::SystemLayer().StartTimer(chip::System::Clock::Milliseconds32(kTimeoutMs + kSleepPadding),
                                                               CheckCommissioningWindowManagerWindowClosedTask, nullptr));
    // Simulate a session establishment error during that window, such that the
    // delay for the error plus the window size exceeds our "timeout + padding" above.
    EXPECT_SUCCESS(
        chip::DeviceLayer::SystemLayer().StartTimer(chip::System::Clock::Milliseconds32(kFailedSessionEstablishmentTimeoutMs),
                                                    SimulateFailedSessionEstablishmentTask, nullptr));

    // Advance time so that SimulateFailedSessionEstablishmentTask is fired
    clock.AdvanceMonotonic(chip::System::Clock::Milliseconds64(kFailedSessionEstablishmentTimeoutMs));
    ServiceEvents();

    // Advance time so that the CheckCommissioningWindowManagerWindowClosedTask is fired
    clock.AdvanceMonotonic(chip::System::Clock::Milliseconds64(kTimeoutMs + kSleepPadding - kFailedSessionEstablishmentTimeoutMs));
    ServiceEvents();

    EXPECT_TRUE(sSimulateFailedSessionEstablishmentTaskCalled);
    EXPECT_TRUE(sCheckCommissioningWindowManagerWindowClosedTaskCalled);

    commissionMgr.SetAppDelegate(nullptr);

    ChipLogError(AppServer, "AMINE: CheckCommissioningWindowManagerWindowTimeoutWithSessionEstablishmentErrors done");
}

TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerEnhancedWindow)
{
    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);
    Spake2pVerifier verifier;
    constexpr uint32_t kIterations = kSpake2p_Min_PBKDF_Iterations;
    uint8_t salt[kSpake2p_Min_PBKDF_Salt_Length];
    chip::ByteSpan saltData(salt);

    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(commissionMgr.MaxCommissioningTimeout(), newDiscriminator, verifier,
                                                            kIterations, saltData, fabricIndex, vendorId),
              CHIP_NO_ERROR);
    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kEnhancedWindowOpen);
    EXPECT_FALSE(chip::DeviceLayer::ConnectivityMgr().IsBLEAdvertisingEnabled());
    EXPECT_FALSE(commissionMgr.GetOpenerFabricIndex().IsNull());
    EXPECT_EQ(commissionMgr.GetOpenerFabricIndex().Value(), fabricIndex);
    EXPECT_FALSE(commissionMgr.GetOpenerVendorId().IsNull());
    EXPECT_EQ(commissionMgr.GetOpenerVendorId().Value(), vendorId);
    EXPECT_TRUE(sWindowStatusDirty);
    EXPECT_TRUE(sAdminFabricIndexDirty);
    EXPECT_TRUE(sAdminVendorIdDirty);

    ResetDirtyFlags();
    EXPECT_FALSE(sWindowStatusDirty);
    EXPECT_FALSE(sAdminFabricIndexDirty);
    EXPECT_FALSE(sAdminVendorIdDirty);

    commissionMgr.CloseCommissioningWindow();
    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());
    EXPECT_EQ(commissionMgr.CommissioningWindowStatusForCluster(),
              chip::app::Clusters::AdministratorCommissioning::CommissioningWindowStatusEnum::kWindowNotOpen);
    EXPECT_TRUE(commissionMgr.GetOpenerFabricIndex().IsNull());
    EXPECT_TRUE(commissionMgr.GetOpenerVendorId().IsNull());
    EXPECT_TRUE(sWindowStatusDirty);
    EXPECT_TRUE(sAdminFabricIndexDirty);
    EXPECT_TRUE(sAdminVendorIdDirty);

    ResetDirtyFlags();

    ChipLogError(AppServer, "AMINE: TestCheckCommissioningWindowManagerEnhancedWindow done");
}

TEST_F(TestCommissioningWindowManager, PASEAtEndOfCommissioningTimeoutClearsPASESession)
{
    System::Clock::Internal::RAIIMockClock clock;

    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    auto kCommissioningTimeout                 = commissionMgr.MinCommissioningTimeout();

    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(kCommissioningTimeout, newDiscriminator, sTestSpake2p01_PASEVerifier,
                                                            sTestSpake2p01_IterationCount, ByteSpan(sTestSpake2p01_Salt),
                                                            fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    clock.AdvanceMonotonic(kCommissioningTimeout - 1_ms);
    ServiceEvents();

    // Establish PASE Handshake to the server's CommissioningWindowManager
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);

    // Ensure that a PASE Session exists for pairingCommissioner
    auto commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
    EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    clock.AdvanceMonotonic(180_s);
    ServiceEvents();
    // Ensure that a PASE Session exists for the CommissioningWindowManager
    // TODO: renable oncce text fixed
    // EXPECT_TRUE(commissionMgr.GetPASESession().HasValue());
    // EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    // clock.AdvanceMonotonic(commissionMgr.MinCommissioningTimeout() - 10_ms);
    // ServiceEvents();

    // This is the equivalent of AdministratorCommissioningLogic::RevokeCommissioning() in the AdministratorCommissioning Cluster
    // RevokeCommissioningCommandEquivalent();

    // We need to service events here to allow the Async Events to be processed and make sure that the CommissioningWindowManager
    // successfully shutdown the PASESession
    // ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());

    clock.AdvanceMonotonic(180_s);
    ServiceEvents();

    // clock.AdvanceMonotonic(commissionMgr.MinCommissioningTimeout() - 10_ms);
    // ServiceEvents();

    // ServiceEvents();
    // ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
}

// TEST_F(TestCommissioningWindowManager, TestCheckCommissioningWindowManagerEnhancedWindow)
// {
//     EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(CheckCommissioningWindowManagerEnhancedWindowTask));
//     EXPECT_SUCCESS(chip::DeviceLayer::PlatformMgr().ScheduleWork(StopEventLoop));
//     chip::DeviceLayer::PlatformMgr().RunEventLoop();
// }

// This function is the equivalent of AdministratorCommissioningLogic::RevokeCommissioning() in the AdministratorCommissioning
// Cluster.
// WARNING: Please keep this function in sync with the actual implementation in the cluster
void RevokeCommissioningCommandEquivalent()
{
    //

    auto & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();

    if (commissionMgr.GetPASESession().HasValue())
    {
        Server::GetInstance().GetFailSafeContext().ForceFailSafeTimerExpiry();
    }

    if (!commissionMgr.IsCommissioningWindowOpen())
    {
        ChipLogError(Zcl, "Commissioning window is currently not open");
        return;
    }

    commissionMgr.CloseCommissioningWindow();
    ChipLogProgress(Zcl, "Commissioning window is now closed");
}

TEST_F(TestCommissioningWindowManager, RevokeCommissioningClearsPASESession)
{
    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(commissionMgr.MaxCommissioningTimeout(), newDiscriminator,
                                                            sTestSpake2p01_PASEVerifier, sTestSpake2p01_IterationCount,
                                                            ByteSpan(sTestSpake2p01_Salt), fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    // Establish PASE Handshake to the server's CommissioningWindowManager
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);

    // Ensure that a PASE Session exists for pairingCommissioner
    auto commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
    EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    // Ensure that a PASE Session exists for the CommissioningWindowManager
    ASSERT_TRUE(commissionMgr.GetPASESession().HasValue());
    EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    // This is the equivalent of AdministratorCommissioningLogic::RevokeCommissioning() in the AdministratorCommissioning Cluster
    RevokeCommissioningCommandEquivalent();

    // We need to service events here to allow the Async Events to be processed and make sure that the CommissioningWindowManager
    // successfully shutdown the PASESession
    ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
}

// - After Completion of PASE Handshake, the Commissionee (CommissioningWindowManager) arms a 60 seconds Fail Safe Timer.
// - Test that On Expiry of this Fail Safe Timer, PASESession will be cleared by the Commissionee

TEST_F(TestCommissioningWindowManager, FailSafeExpiryClearsPASESession)
{

    System::Clock::Internal::RAIIMockClock clock;

    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    auto kTimeoutMs                            = commissionMgr.MinCommissioningTimeout();
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(kTimeoutMs, newDiscriminator, sTestSpake2p01_PASEVerifier,
                                                            sTestSpake2p01_IterationCount, ByteSpan(sTestSpake2p01_Salt),
                                                            fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    // Establish PASE Handshake to the server's CommissioningWindowManager
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);

    // Ensure that a PASE Session exists for pairingCommissioner
    auto commissionerSession = pairingCommissioner.CopySecureSession();
    ASSERT_TRUE(commissionerSession.HasValue());
    EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    // Ensure that a PASE Session exists for the CommissioningWindowManager
    ASSERT_TRUE(commissionMgr.GetPASESession().HasValue());
    EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    EXPECT_TRUE(Server::GetInstance().GetFailSafeContext().IsFailSafeArmed());

    // After PASE completion, the fail safe is armed  with expiryLengthSeconds=60 seconds, so we advance time by that amount and
    // check that PASESession is cleared
    auto FailSafeTimeoutAfterPASECompletion = 60_s;
    clock.AdvanceMonotonic(FailSafeTimeoutAfterPASECompletion);
    ServiceEvents();

    EXPECT_FALSE(Server::GetInstance().GetFailSafeContext().IsFailSafeArmed());

    // TODO: do i need this?
    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
}

/******************** */
// Delay before PASE is established
TEST_F(TestCommissioningWindowManager, DELAYPASEFailSafeExpiryClearsPASESession)
{

    System::Clock::Internal::RAIIMockClock clock;

    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();

    MockAppDelegate delegateApp;
    commissionMgr.SetAppDelegate(&delegateApp);

    auto kTimeoutMs = commissionMgr.MinCommissioningTimeout();
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(kTimeoutMs, newDiscriminator, sTestSpake2p01_PASEVerifier,
                                                            sTestSpake2p01_IterationCount, ByteSpan(sTestSpake2p01_Salt),
                                                            fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    EXPECT_EQ(delegateApp.mNumSessionEstablishmentErrors, 0u);

    clock.AdvanceMonotonic(kTimeoutMs);
    ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // after commissioning window has closed, CommissioningWindowManager should NOT be listening for PASE (and should NOT be
    // listening for PBKDFParamRequest)
    ASSERT_FALSE(commissionMgr.IsListeningForPASE());

    // Establish PASE Handshake to the server's CommissioningWindowManager
    // TODO: Remove this, since this will fail anyways ?
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);
    ServiceEvents();
    // Since the commissioning window is not Listening for PBKDFParamRequest anymore, PASE will fail on the Responder Side and the
    // AppDelegate will be notified of a SessionEstablishmentError
    EXPECT_EQ(delegateApp.mNumSessionEstablishmentErrors, 1u);

    // TODO, shold I remove this? try to use PASESession
    EXPECT_EQ(delegateCommissioner.mNumPairingErrors, 0u);
    EXPECT_EQ(delegateCommissioner.mNumPairingComplete, 0u);

    // Ensure that a PASE Session exists for pairingCommissioner
    auto commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
    EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    // Ensure that a PASE Session exists for the CommissioningWindowManager
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());
    // This fails in this case
    // EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    EXPECT_FALSE(Server::GetInstance().GetFailSafeContext().IsFailSafeArmed());

    // After PASE completion, the fail safe is armed  with expiryLengthSeconds=60 seconds, so we advance time by that amount and
    // check that PASESession is cleared
    auto FailSafeTimeoutAfterPASECompletion = 60_s;
    clock.AdvanceMonotonic(FailSafeTimeoutAfterPASECompletion);
    ServiceEvents();

    EXPECT_FALSE(Server::GetInstance().GetFailSafeContext().IsFailSafeArmed());

    // TODO: do i need this?
    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_FALSE(commissionerSession.HasValue());

    commissionMgr.SetAppDelegate(nullptr);
}

// RevokeCommissioning called after commissioning Window times out but BEFORE fail-safe timer expires.
// The aim is to ensure that Revoke Commissioning forces Fail-Safe expiry and clears PASESession EVEN when Commissioning Window is
// Closed.
// This is a corner case that is not covered in Spec, that could happen if we establish PASE towards the end of the commissioning
// window, and then the administrator calls RevokeCommissioning. But the call to RevokeCommissioning should still clear the
// PASESession.
TEST_F(TestCommissioningWindowManager, RevokeCommissioningAfterCommissioningTimeoutClearsPASESession)
{
    System::Clock::Internal::RAIIMockClock clock;

    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(commissionMgr.MinCommissioningTimeout(), newDiscriminator,
                                                            sTestSpake2p01_PASEVerifier, sTestSpake2p01_IterationCount,
                                                            ByteSpan(sTestSpake2p01_Salt), fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    auto timeout = commissionMgr.MinCommissioningTimeout();
    clock.AdvanceMonotonic(timeout - 300_ms);
    ServiceEvents();

    // Establish PASE Handshake to the server's CommissioningWindowManager
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);

    // Ensure that a PASE Session exists for pairingCommissioner
    auto commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
    EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    // Ensure that a PASE Session exists for the CommissioningWindowManager
    //   EXPECT_TRUE(commissionMgr.GetPASESession().HasValue());
    // EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    // clock.AdvanceMonotonic(180_s - 10_ms);
    clock.AdvanceMonotonic(300_ms);
    ServiceEvents();

    // This is the equivalent of AdministratorCommissioningLogic::RevokeCommissioning() in the AdministratorCommissioning Cluster
    RevokeCommissioningCommandEquivalent();

    // We need to service events here to allow the Async Events to be processed and make sure that the CommissioningWindowManager
    // successfully shutdown the PASESession
    ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());

    clock.AdvanceMonotonic(200_s);
    ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
}

#if CHIP_WITH_NLFAULTINJECTION

// PARTIAL PASE
constexpr uint8_t kFaultInjectionSuccessCode = 0;
// class PASETestLoopbackTransportDelegate : public Test::LoopbackTransportDelegate
// {
// public:
//     void OnMessageDropped() override { mMessageDropped = true; }
//     bool mMessageDropped = false;
// };
TEST_F(TestCommissioningWindowManager, PartialPASESession)
{
    System::Clock::Internal::RAIIMockClock clock;

    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(commissionMgr.MinCommissioningTimeout(), newDiscriminator,
                                                            sTestSpake2p01_PASEVerifier, sTestSpake2p01_IterationCount,
                                                            ByteSpan(sTestSpake2p01_Salt), fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    auto timeout = commissionMgr.MinCommissioningTimeout();
    // clock.AdvanceMonotonic(timeout - 300_ms);
    ServiceEvents();

    // EXPECT_EQ(chip::FaultInjection::GetManager().FailAtFault(chip::FaultInjection::kFault_PASESkipSendingPAKE3, 0, 1),
    //           kFaultInjectionSuccessCode);

    // Establish PASE Handshake to the server's CommissioningWindowManager
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);

    // Ensure that a PASE Session exists for pairingCommissioner
    // auto commissionerSession = pairingCommissioner.CopySecureSession();
    // EXPECT_TRUE(commissionerSession.HasValue());
    // EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    // Ensure that a PASE Session exists for the CommissioningWindowManager
    //   EXPECT_TRUE(commissionMgr.GetPASESession().HasValue());
    // EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    // clock.AdvanceMonotonic(180_s - 10_ms);
    // ServiceEvents();

    // This is the equivalent of AdministratorCommissioningLogic::RevokeCommissioning() in the AdministratorCommissioning Cluster
    RevokeCommissioningCommandEquivalent();
    DrainAndServiceIO();

    // We need to service events here to allow the Async Events to be processed and make sure that the CommissioningWindowManager
    // successfully shutdown the PASESession
    ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    // commissionerSession = pairingCommissioner.CopySecureSession();
    // EXPECT_TRUE(commissionerSession.HasValue());

    clock.AdvanceMonotonic(200_s);
    ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    // commissionerSession = pairingCommissioner.CopySecureSession();
    // EXPECT_TRUE(commissionerSession.HasValue());
}
#endif // CHIP_WITH_NLFAULTINJECTION

TEST_F(TestCommissioningWindowManager, SimulatePartialPASEHandshake)
{
    TemporarySessionManager sessionManager(*this);
    TestSecurePairingDelegate delegateCommissioner, delegateAccessory;
    PASESession pairingCommissioner, pairingAccessory;
    auto & loopback = GetLoopback();
    loopback.Reset();
    // loopback.mSentMessageCount = 0;
    // // Drop the second message, simulating a network loss
    // loopback.mNumMessagesToDrop = 0;

    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);
}

TEST_F(TestCommissioningWindowManager, DELETEME_PASEAtEndOfCommissioningTimeoutClearsPASESession)
{
    System::Clock::Internal::RAIIMockClock clock;

    TemporarySessionManager sessionManager(*this);

    TestSecurePairingDelegate delegateCommissioner;
    PASESession pairingCommissioner;
    auto & loopback = GetLoopback();
    loopback.Reset();

    // Open an Enhanced Commissioning Window
    uint16_t originDiscriminator;
    EXPECT_EQ(chip::DeviceLayer::GetCommissionableDataProvider()->GetSetupDiscriminator(originDiscriminator), CHIP_NO_ERROR);
    uint16_t newDiscriminator = static_cast<uint16_t>(originDiscriminator + 1);

    constexpr auto fabricIndex = static_cast<chip::FabricIndex>(1);
    constexpr auto vendorId    = static_cast<chip::VendorId>(0xFFF3);

    CommissioningWindowManager & commissionMgr = Server::GetInstance().GetCommissioningWindowManager();
    EXPECT_EQ(commissionMgr.OpenEnhancedCommissioningWindow(commissionMgr.MinCommissioningTimeout(), newDiscriminator,
                                                            sTestSpake2p01_PASEVerifier, sTestSpake2p01_IterationCount,
                                                            ByteSpan(sTestSpake2p01_Salt), fabricIndex, vendorId),
              CHIP_NO_ERROR);

    EXPECT_TRUE(commissionMgr.IsCommissioningWindowOpen());

    ServiceEvents();

    loopback.mSentMessageCount = 0;
    // // // Drop the second message, simulating a network loss
    loopback.mNumMessagesToDrop = 1;

    // Establish PASE Handshake to the server's CommissioningWindowManager
    EstablishPASEHandshake(sessionManager, pairingCommissioner, delegateCommissioner);

    // Ensure that a PASE Session exists for pairingCommissioner
    auto commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
    EXPECT_TRUE(commissionerSession.Value()->AsSecureSession()->IsPASESession());

    clock.AdvanceMonotonic(360_s);
    ServiceEvents();
    // Ensure that a PASE Session exists for the CommissioningWindowManager
    // TODO: renable oncce text fixed
    // EXPECT_TRUE(commissionMgr.GetPASESession().HasValue());
    // EXPECT_TRUE(commissionMgr.GetPASESession().Value()->AsSecureSession()->IsPASESession());

    // clock.AdvanceMonotonic(commissionMgr.MinCommissioningTimeout() - 10_ms);
    // ServiceEvents();

    // This is the equivalent of AdministratorCommissioningLogic::RevokeCommissioning() in the AdministratorCommissioning Cluster
    // RevokeCommissioningCommandEquivalent();

    // We need to service events here to allow the Async Events to be processed and make sure that the CommissioningWindowManager
    // successfully shutdown the PASESession
    // ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());

    clock.AdvanceMonotonic(180_s);
    ServiceEvents();

    // clock.AdvanceMonotonic(commissionMgr.MinCommissioningTimeout() - 10_ms);
    // ServiceEvents();

    // ServiceEvents();
    // ServiceEvents();

    EXPECT_FALSE(commissionMgr.IsCommissioningWindowOpen());

    // This asserts that the CommissioningWindowManager has cleared the PASESession
    EXPECT_FALSE(commissionMgr.GetPASESession().HasValue());

    // Asserting that PASESession is still present on the Commissioner side
    commissionerSession = pairingCommissioner.CopySecureSession();
    EXPECT_TRUE(commissionerSession.HasValue());
}
} // namespace

#pragma clang diagnostic pop
