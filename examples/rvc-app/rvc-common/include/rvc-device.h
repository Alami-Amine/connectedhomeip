#pragma once

#include "rvc-mode-delegates.h"
#include "rvc-operational-state-delegate.h"
#include "rvc-service-area-delegate.h"
#include "rvc-service-area-storage-delegate.h"
#include <app/clusters/mode-base-server/mode-base-server.h>
#include <app/clusters/operational-state-server/operational-state-server.h>
#include <app/clusters/service-area-server/service-area-delegate.h>
#include <app/clusters/service-area-server/service-area-server.h>

#include <string>

namespace chip {
namespace app {
namespace Clusters {

class RvcDevice
{
private:
    RvcRunMode::RvcRunModeDelegate mRunModeDelegate;
    ModeBase::Instance mRunModeInstance;

    RvcCleanMode::RvcCleanModeDelegate mCleanModeDelegate;
    ModeBase::Instance mCleanModeInstance;

    RvcOperationalState::RvcOperationalStateDelegate mOperationalStateDelegate;
    RvcOperationalState::Instance mOperationalStateInstance;

    ServiceArea::RvcServiceAreaDelegate mServiceAreaDelegate;
    ServiceArea::RvcServiceAreaStorageDelegate mStorageDelegate;
    ServiceArea::Instance mServiceAreaInstance;

    bool mDocked   = false;
    bool mCharging = false;

    uint8_t mStateBeforePause = 0;

public:
    /**
     * This class is responsible for initialising all the RVC clusters and managing the interactions between them as required by
     * the specific "business logic". See the state machine diagram.
     * @param aRvcClustersEndpoint The endpoint ID where all the RVC clusters exist.
     */
    explicit RvcDevice(EndpointId aRvcClustersEndpoint) :
        mRunModeDelegate(), mRunModeInstance(&mRunModeDelegate, aRvcClustersEndpoint, RvcRunMode::Id, 0), mCleanModeDelegate(),
        mCleanModeInstance(&mCleanModeDelegate, aRvcClustersEndpoint, RvcCleanMode::Id, 0), mOperationalStateDelegate(),
        mOperationalStateInstance(&mOperationalStateDelegate, aRvcClustersEndpoint), mServiceAreaDelegate(),
        mServiceAreaInstance(&mStorageDelegate, &mServiceAreaDelegate, aRvcClustersEndpoint,
                             BitMask<ServiceArea::Feature>(ServiceArea::Feature::kMaps, ServiceArea::Feature::kProgressReporting))
    {
        // set the current-mode at start-up
        mRunModeInstance.UpdateCurrentMode(RvcRunMode::ModeIdle);

        // Hypothetically, the device checks if it is physically docked or charging
        SetDeviceToIdleState();

        // set callback functions
        mRunModeDelegate.SetHandleChangeToMode(&RvcDevice::HandleRvcRunChangeToMode, this);
        mCleanModeDelegate.SetHandleChangeToMode(&RvcDevice::HandleRvcCleanChangeToMode, this);
        mOperationalStateDelegate.SetPauseCallback(&RvcDevice::HandleOpStatePauseCallback, this);
        mOperationalStateDelegate.SetResumeCallback(&RvcDevice::HandleOpStateResumeCallback, this);
        mOperationalStateDelegate.SetGoHomeCallback(&RvcDevice::HandleOpStateGoHomeCallback, this);

        mServiceAreaDelegate.SetIsSetSelectedAreasAllowedCallback(&RvcDevice::SaIsSetSelectedAreasAllowed, this);
        mServiceAreaDelegate.SetHandleSkipAreaCallback(&RvcDevice::SaHandleSkipArea, this);
        mServiceAreaDelegate.SetIsSupportedAreasChangeAllowedCallback(&RvcDevice::SaIsSupportedAreasChangeAllowed, this);
        mServiceAreaDelegate.SetIsSupportedMapChangeAllowedCallback(&RvcDevice::SaIsSupportedMapChangeAllowed, this);
    }

    /**
     * Init all the clusters used by this device.
     */
    void Init();

    /**
     * Sets the device to an idle state, that is either the STOPPED, DOCKED or CHARGING state, depending on physical information.
     * Note: in this example this is based on the mDocked and mChanging boolean variables.
     */
    void SetDeviceToIdleState();

    /**
     * Handles the RvcRunMode command requesting a mode change.
     */
    void HandleRvcRunChangeToMode(uint8_t newMode, ModeBase::Commands::ChangeToModeResponse::Type & response);

    /**
     * Handles the RvcCleanMode command requesting a mode change.
     */
    void HandleRvcCleanChangeToMode(uint8_t newMode, ModeBase::Commands::ChangeToModeResponse::Type & response);

    /**
     * Handles the RvcOperationalState pause command.
     */
    void HandleOpStatePauseCallback(Clusters::OperationalState::GenericOperationalError & err);

    /**
     * Handles the RvcOperationalState resume command.
     */
    void HandleOpStateResumeCallback(Clusters::OperationalState::GenericOperationalError & err);

    /**
     * Handles the RvcOperationalState GoHome command.
     */
    void HandleOpStateGoHomeCallback(Clusters::OperationalState::GenericOperationalError & err);

    bool SaIsSetSelectedAreasAllowed(MutableCharSpan & statusText);

    bool SaHandleSkipArea(uint32_t skippedArea, MutableCharSpan & skipStatusText);

    bool SaIsSupportedAreasChangeAllowed();

    bool SaIsSupportedMapChangeAllowed();

    /**
     * Updates the state machine when the device becomes fully-charged.
     */
    void HandleChargedMessage();

    void HandleChargingMessage();

    void HandleDockedMessage();

    void HandleEmptyingDustBinMessage();

    void HandleCleaningMopMessage();

    void HandleFillingWaterTankMessage();

    void HandleUpdatingMapsMessage();

    void HandleChargerFoundMessage();

    void HandleLowChargeMessage();

    void HandleActivityCompleteEvent();

    void HandleAreaCompletedEvent();

    void HandleAddServiceAreaMap(uint32_t mapId, const CharSpan & mapName);

    void HandleAddServiceAreaArea(ServiceArea::AreaStructureWrapper & area);

    void HandleRemoveServiceAreaMap(uint32_t mapId);

    void HandleRemoveServiceAreaArea(uint32_t areaId);

    /**
     * Sets the device to an error state with the error state ID matching the error name given.
     * @param error The error name. Could be one of UnableToStartOrResume, UnableToCompleteOperation, CommandInvalidInState,
     * FailedToFindChargingDock, Stuck, DustBinMissing, DustBinFull, WaterTankEmpty, WaterTankMissing, WaterTankLidOpen or
     * MopCleaningPadMissing.
     */
    void HandleErrorEvent(const std::string & error);

    void HandleClearErrorMessage();

    void HandleResetMessage();

    /**
     * Updates the Service area progress elements when an activity has ended.
     * Sets any remaining Operating or Pending states to Skipped.
     */
    void UpdateServiceAreaProgressOnExit();
};

} // namespace Clusters
} // namespace app
} // namespace chip
