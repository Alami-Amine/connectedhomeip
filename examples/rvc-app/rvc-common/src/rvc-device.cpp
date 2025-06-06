#include "rvc-device.h"

#include <string>

using namespace chip::app::Clusters;

void RvcDevice::Init()
{
    mServiceAreaInstance.Init();
    mRunModeInstance.Init();
    mCleanModeInstance.Init();
    mOperationalStateInstance.Init();
}

void RvcDevice::SetDeviceToIdleState()
{
    if (mCharging)
    {
        mDocked = true;
        mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kCharging));
    }
    else if (mDocked)
    {
        mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kDocked));
    }
    else
    {
        mOperationalStateInstance.SetOperationalState(to_underlying(OperationalState::OperationalStateEnum::kStopped));
    }
}

void RvcDevice::HandleRvcRunChangeToMode(uint8_t newMode, ModeBase::Commands::ChangeToModeResponse::Type & response)
{
    uint8_t currentState = mOperationalStateInstance.GetCurrentOperationalState();
    uint8_t currentMode  = mRunModeInstance.GetCurrentMode();

    switch (currentState)
    {
    case to_underlying(OperationalState::OperationalStateEnum::kStopped):
    case to_underlying(RvcOperationalState::OperationalStateEnum::kDocked):
    case to_underlying(RvcOperationalState::OperationalStateEnum::kCharging): {
        // We could be in the charging state with an RvcRun mode != idle.
        if (currentMode != RvcRunMode::ModeIdle && newMode != RvcRunMode::ModeIdle)
        {
            response.status = to_underlying(ModeBase::StatusCode::kInvalidInMode);
            response.statusText.SetValue("Change to the mapping or cleaning mode is only allowed from idle"_span);
            return;
        }

        mCharging = false;
        mDocked   = false;
        mRunModeInstance.UpdateCurrentMode(newMode);
        mOperationalStateInstance.SetOperationalState(to_underlying(OperationalState::OperationalStateEnum::kRunning));
        mServiceAreaDelegate.SetAttributesAtCleanStart();
        response.status = to_underlying(ModeBase::StatusCode::kSuccess);
        return;
    }
    break;
    case to_underlying(OperationalState::OperationalStateEnum::kRunning): {
        if (newMode != RvcRunMode::ModeIdle)
        {
            response.status = to_underlying(ModeBase::StatusCode::kInvalidInMode);
            response.statusText.SetValue("Change to the mapping or cleaning mode is only allowed from idle"_span);
            return;
        }

        mRunModeInstance.UpdateCurrentMode(newMode);
        mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger));
        response.status = to_underlying(ModeBase::StatusCode::kSuccess);

        UpdateServiceAreaProgressOnExit();
        return;
    }
    break;
    }

    // If we fall through at any point, it's because the change is not supported in the current state.
    response.status = to_underlying(ModeBase::StatusCode::kInvalidInMode);
    response.statusText.SetValue("This change is not allowed at this time"_span);
}

void RvcDevice::HandleRvcCleanChangeToMode(uint8_t newMode, ModeBase::Commands::ChangeToModeResponse::Type & response)
{
    uint8_t rvcRunCurrentMode = mRunModeInstance.GetCurrentMode();

    if (rvcRunCurrentMode != RvcRunMode::ModeIdle)
    {
        response.status = to_underlying(ModeBase::StatusCode::kInvalidInMode);
        response.statusText.SetValue("Change of the cleaning mode is only allowed in Idle."_span);
        return;
    }

    response.status = to_underlying(ModeBase::StatusCode::kSuccess);
}

void RvcDevice::HandleOpStatePauseCallback(Clusters::OperationalState::GenericOperationalError & err)
{
    // This method is only called if the device is in a Pause-compatible state, i.e. `Running` or `SeekingCharger`.
    mStateBeforePause = mOperationalStateInstance.GetCurrentOperationalState();
    auto error = mOperationalStateInstance.SetOperationalState(to_underlying(OperationalState::OperationalStateEnum::kPaused));
    err.Set((error == CHIP_NO_ERROR) ? to_underlying(OperationalState::ErrorStateEnum::kNoError)
                                     : to_underlying(OperationalState::ErrorStateEnum::kUnableToCompleteOperation));
}

void RvcDevice::HandleOpStateResumeCallback(Clusters::OperationalState::GenericOperationalError & err)
{
    uint8_t targetState = to_underlying(OperationalState::OperationalStateEnum::kRunning);

    switch (mOperationalStateInstance.GetCurrentOperationalState())
    {
    case to_underlying(RvcOperationalState::OperationalStateEnum::kCharging):
    case to_underlying(RvcOperationalState::OperationalStateEnum::kDocked): {
        if (mRunModeInstance.GetCurrentMode() != RvcRunMode::ModeCleaning &&
            mRunModeInstance.GetCurrentMode() != RvcRunMode::ModeMapping)
        {
            err.Set(to_underlying(OperationalState::ErrorStateEnum::kCommandInvalidInState));
            return;
        }
    }
    break;
    case to_underlying(OperationalState::OperationalStateEnum::kPaused): {
        if (mStateBeforePause == to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger))
        {
            targetState = to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger);
        }
    }
    break;
    default:
        // This method is only called if the device is in a resume-compatible state, i.e. `Charging`, `Docked` or
        // `Paused`. Therefore, we do not expect to ever enter this branch.
        err.Set(to_underlying(OperationalState::ErrorStateEnum::kCommandInvalidInState));
        return;
    }

    auto error = mOperationalStateInstance.SetOperationalState(targetState);

    err.Set((error == CHIP_NO_ERROR) ? to_underlying(OperationalState::ErrorStateEnum::kNoError)
                                     : to_underlying(OperationalState::ErrorStateEnum::kUnableToCompleteOperation));
}

void RvcDevice::HandleOpStateGoHomeCallback(Clusters::OperationalState::GenericOperationalError & err)
{
    switch (mOperationalStateInstance.GetCurrentOperationalState())
    {
    case to_underlying(OperationalState::OperationalStateEnum::kStopped): {
        if (mRunModeInstance.GetCurrentMode() != RvcRunMode::ModeIdle)
        {
            err.Set(to_underlying(OperationalState::ErrorStateEnum::kCommandInvalidInState));
            return;
        }

        auto error = mOperationalStateInstance.SetOperationalState(
            to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger));

        err.Set((error == CHIP_NO_ERROR) ? to_underlying(OperationalState::ErrorStateEnum::kNoError)
                                         : to_underlying(OperationalState::ErrorStateEnum::kUnableToCompleteOperation));
    }
    break;
    default:
        err.Set(to_underlying(OperationalState::ErrorStateEnum::kCommandInvalidInState));
        return;
    }
}

bool RvcDevice::SaIsSetSelectedAreasAllowed(MutableCharSpan & statusText)
{
    if (mOperationalStateInstance.GetCurrentOperationalState() == to_underlying(OperationalState::OperationalStateEnum::kRunning))
    {
        CopyCharSpanToMutableCharSpanWithTruncation("cannot set the Selected Areas while the device is running"_span, statusText);
        return false;
    }
    return true;
}

bool RvcDevice::SaHandleSkipArea(uint32_t skippedArea, MutableCharSpan & skipStatusText)
{
    if (mServiceAreaInstance.GetCurrentArea() != skippedArea)
    {
        // This device only supports skipping the current location.
        CopyCharSpanToMutableCharSpanWithTruncation("the skipped area does not match the current area"_span, skipStatusText);
        return false;
    }

    if (mOperationalStateInstance.GetCurrentOperationalState() != to_underlying(OperationalState::OperationalStateEnum::kRunning))
    {
        // This device only accepts the skip are command while in the running state
        CopyCharSpanToMutableCharSpanWithTruncation("skip area is only accepted when the device is running"_span, skipStatusText);
        return false;
    }

    bool finished;
    mServiceAreaDelegate.GoToNextArea(ServiceArea::OperationalStatusEnum::kSkipped, finished);

    if (finished)
    {
        HandleActivityCompleteEvent();
    }

    return true;
}

bool RvcDevice::SaIsSupportedAreasChangeAllowed()
{
    return mOperationalStateInstance.GetCurrentOperationalState() !=
        to_underlying(OperationalState::OperationalStateEnum::kRunning);
}

bool RvcDevice::SaIsSupportedMapChangeAllowed()
{
    return mOperationalStateInstance.GetCurrentOperationalState() !=
        to_underlying(OperationalState::OperationalStateEnum::kRunning);
}

void RvcDevice::HandleChargedMessage()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() !=
        to_underlying(RvcOperationalState::OperationalStateEnum::kCharging))
    {
        ChipLogError(NotSpecified, "RVC App: The 'Charged' command is only accepted when the device is in the 'Charging' state.");
        return;
    }

    mCharging = false;

    if (mRunModeInstance.GetCurrentMode() == RvcRunMode::ModeIdle)
    {
        if (mDocked) // assuming that we can't be charging the device while it is not docked.
        {
            mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kDocked));
        }
        else
        {
            mOperationalStateInstance.SetOperationalState(to_underlying(OperationalState::OperationalStateEnum::kStopped));
        }
    }
    else
    {
        mOperationalStateInstance.SetOperationalState(to_underlying(OperationalState::OperationalStateEnum::kRunning));
    }
}

void RvcDevice::HandleChargingMessage()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() != to_underlying(RvcOperationalState::OperationalStateEnum::kDocked))
    {
        ChipLogError(NotSpecified, "RVC App: The 'Charging' command is only accepted when the device is in the 'Docked' state.");
        return;
    }

    mCharging = true;

    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kCharging));
}

void RvcDevice::HandleDockedMessage()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() != to_underlying(OperationalState::OperationalStateEnum::kStopped))
    {
        ChipLogError(NotSpecified, "RVC App: The 'Docked' command is only accepted when the device is in the 'Stopped' state.");
        return;
    }

    mDocked = true;

    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kDocked));
}

void RvcDevice::HandleEmptyingDustBinMessage()
{
    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kEmptyingDustBin));
}

void RvcDevice::HandleCleaningMopMessage()
{
    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kCleaningMop));
}

void RvcDevice::HandleFillingWaterTankMessage()
{
    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kFillingWaterTank));
}

void RvcDevice::HandleUpdatingMapsMessage()
{
    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kUpdatingMaps));
}

void RvcDevice::HandleChargerFoundMessage()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() !=
        to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger))
    {
        ChipLogError(NotSpecified,
                     "RVC App: The 'ChargerFound' command is only accepted when the device is in the 'SeekingCharger' state.");
        return;
    }

    mCharging = true;
    mDocked   = true;

    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kCharging));
}

void RvcDevice::HandleLowChargeMessage()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() != to_underlying(OperationalState::OperationalStateEnum::kRunning))
    {
        ChipLogError(NotSpecified, "RVC App: The 'LowCharge' command is only accepted when the device is in the 'Running' state.");
        return;
    }

    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger));
}

void RvcDevice::HandleActivityCompleteEvent()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() != to_underlying(OperationalState::OperationalStateEnum::kRunning))
    {
        ChipLogError(NotSpecified,
                     "RVC App: The 'ActivityComplete' command is only accepted when the device is in the 'Running' state.");
        return;
    }

    mRunModeInstance.UpdateCurrentMode(RvcRunMode::ModeIdle);

    Optional<DataModel::Nullable<uint32_t>> a(DataModel::Nullable<uint32_t>(100));
    Optional<DataModel::Nullable<uint32_t>> b(DataModel::Nullable<uint32_t>(10));
    mOperationalStateInstance.OnOperationCompletionDetected(0, a, b);

    mOperationalStateInstance.SetOperationalState(to_underlying(RvcOperationalState::OperationalStateEnum::kSeekingCharger));

    mServiceAreaInstance.SetCurrentArea(DataModel::NullNullable);
    mServiceAreaInstance.SetEstimatedEndTime(DataModel::NullNullable);
    UpdateServiceAreaProgressOnExit();
}

void RvcDevice::HandleAreaCompletedEvent()
{
    bool finished;
    mServiceAreaDelegate.GoToNextArea(ServiceArea::OperationalStatusEnum::kCompleted, finished);

    if (finished)
    {
        HandleActivityCompleteEvent();
    }
}

void RvcDevice::HandleAddServiceAreaMap(uint32_t mapId, const CharSpan & mapName)
{
    mServiceAreaInstance.AddSupportedMap(mapId, mapName);
}

void RvcDevice::HandleAddServiceAreaArea(ServiceArea::AreaStructureWrapper & area)
{
    mServiceAreaInstance.AddSupportedArea(area);
}

void RvcDevice::HandleRemoveServiceAreaMap(uint32_t mapId)
{
    mServiceAreaInstance.RemoveSupportedMap(mapId);
}

void RvcDevice::HandleRemoveServiceAreaArea(uint32_t areaId)
{
    mServiceAreaInstance.RemoveSupportedArea(areaId);
}

void RvcDevice::HandleErrorEvent(const std::string & error)
{
    detail::Structs::ErrorStateStruct::Type err;

    if (error == "UnableToStartOrResume")
    {
        err.errorStateID = to_underlying(OperationalState::ErrorStateEnum::kUnableToStartOrResume);
    }
    else if (error == "UnableToCompleteOperation")
    {
        err.errorStateID = to_underlying(OperationalState::ErrorStateEnum::kUnableToCompleteOperation);
    }
    else if (error == "CommandInvalidInState")
    {
        err.errorStateID = to_underlying(OperationalState::ErrorStateEnum::kCommandInvalidInState);
    }
    else if (error == "FailedToFindChargingDock")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kFailedToFindChargingDock);
    }
    else if (error == "Stuck")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kStuck);
    }
    else if (error == "DustBinMissing")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kDustBinMissing);
    }
    else if (error == "DustBinFull")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kDustBinFull);
    }
    else if (error == "WaterTankEmpty")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kWaterTankEmpty);
    }
    else if (error == "WaterTankMissing")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kWaterTankMissing);
    }
    else if (error == "WaterTankLidOpen")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kWaterTankLidOpen);
    }
    else if (error == "MopCleaningPadMissing")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kMopCleaningPadMissing);
    }
    else if (error == "LowBattery")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kLowBattery);
    }
    else if (error == "CannotReachTargetArea")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kCannotReachTargetArea);
    }
    else if (error == "DirtyWaterTankFull")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kDirtyWaterTankFull);
    }
    else if (error == "DirtyWaterTankMissing")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kDirtyWaterTankMissing);
    }
    else if (error == "WheelsJammed")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kWheelsJammed);
    }
    else if (error == "BrushJammed")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kBrushJammed);
    }
    else if (error == "NavigationSensorObscured")
    {
        err.errorStateID = to_underlying(RvcOperationalState::ErrorStateEnum::kNavigationSensorObscured);
    }
    else
    {
        ChipLogError(NotSpecified, "Unhandled command: The 'Error' key of the 'ErrorEvent' message is not valid.");
        return;
    }

    mOperationalStateInstance.OnOperationalErrorDetected(err);
}

void RvcDevice::HandleClearErrorMessage()
{
    if (mOperationalStateInstance.GetCurrentOperationalState() != to_underlying(OperationalState::OperationalStateEnum::kError))
    {
        ChipLogError(NotSpecified, "RVC App: The 'ClearError' command is only excepted when the device is in the 'Error' state.");
        return;
    }

    mRunModeInstance.UpdateCurrentMode(RvcRunMode::ModeIdle);
    SetDeviceToIdleState();
}

void RvcDevice::HandleResetMessage()
{
    mRunModeInstance.UpdateCurrentMode(RvcRunMode::ModeIdle);
    mOperationalStateInstance.SetOperationalState(to_underlying(OperationalState::OperationalStateEnum::kStopped));
    mCleanModeInstance.UpdateCurrentMode(RvcCleanMode::ModeQuick);

    mServiceAreaInstance.ClearSelectedAreas();
    mServiceAreaInstance.ClearProgress();
    mServiceAreaInstance.SetCurrentArea(DataModel::NullNullable);
    mServiceAreaInstance.SetEstimatedEndTime(DataModel::NullNullable);

    mServiceAreaDelegate.SetMapTopology();
}

void RvcDevice::UpdateServiceAreaProgressOnExit()
{
    if (!mServiceAreaInstance.HasFeature(ServiceArea::Feature::kProgressReporting))
    {
        return;
    }

    uint32_t i = 0;
    ServiceArea::Structs::ProgressStruct::Type progressElement;
    while (mServiceAreaInstance.GetProgressElementByIndex(i, progressElement))
    {
        if (progressElement.status == ServiceArea::OperationalStatusEnum::kOperating ||
            progressElement.status == ServiceArea::OperationalStatusEnum::kPending)
        {
            mServiceAreaInstance.SetProgressStatus(progressElement.areaID, ServiceArea::OperationalStatusEnum::kSkipped);
        }
        i++;
    }
}
