/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
 *    All rights reserved.
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

#include "AmebaTestEventTriggerDelegate.h"
#include "SmokeCOAlarmManager.h"

using namespace ::chip::DeviceLayer;

bool AmebaHandleGlobalTestEventTrigger(uint64_t eventTrigger)
{
    // Customer can trigger action on the Ameba layer based on the eventTrigger
    ChipLogProgress(Support, "[AmebaHandleGlobalTestEventTrigger] Received Event Trigger: 0x%016llx", eventTrigger);
    return false;
}

namespace chip {

bool AmebaTestEventTriggerDelegate::DoesEnableKeyMatch(const ByteSpan & enableKey) const
{
    return !mEnableKey.empty() && mEnableKey.data_equal(enableKey);
}

CHIP_ERROR AmebaTestEventTriggerDelegate::HandleEventTrigger(uint64_t eventTrigger)
{
    eventTrigger = clearEndpointInEventTrigger(eventTrigger);
    // WARNING: LEGACY SUPPORT ONLY, DO NOT EXTEND FOR STANDARD CLUSTERS
    return (AmebaHandleGlobalTestEventTrigger(eventTrigger)) ? CHIP_NO_ERROR : CHIP_ERROR_INVALID_ARGUMENT;
}

} // namespace chip
