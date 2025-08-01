/*
 *    Copyright (c) 2025 Project CHIP Authors
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
#pragma once

#include <app/AttributeValueEncoder.h>
#include <app/data-model-provider/MetadataTypes.h>
#include <clusters/SoftwareDiagnostics/Enums.h>
#include <lib/core/CHIPError.h>
#include <lib/support/ReadOnlyBuffer.h>
#include <platform/DiagnosticDataProvider.h>

namespace chip {
namespace app {
namespace Clusters {

struct SoftwareDiagnosticsEnabledAttributes
{
    bool enableThreadMetrics : 1;
    bool enableCurrentHeapFree : 1;
    bool enableCurrentHeapUsed : 1;
    bool enableCurrentWatermarks : 1;
};

/// Type-safe implementation for callbacks for the SoftwareDiagnostics server
class SoftwareDiagnosticsLogic
{
public:
    SoftwareDiagnosticsLogic(const SoftwareDiagnosticsEnabledAttributes & enabledAttributes) : mEnabledAttributes(enabledAttributes)
    {}
    virtual ~SoftwareDiagnosticsLogic() = default;

    CHIP_ERROR GetCurrentHeapFree(uint64_t & out) const { return DeviceLayer::GetDiagnosticDataProvider().GetCurrentHeapFree(out); }
    CHIP_ERROR GetCurrentHeapUsed(uint64_t & out) const { return DeviceLayer::GetDiagnosticDataProvider().GetCurrentHeapUsed(out); }
    CHIP_ERROR GetCurrentHighWatermark(uint64_t & out) const
    {
        return DeviceLayer::GetDiagnosticDataProvider().GetCurrentHeapHighWatermark(out);
    }

    // Encodes the thread metrics list, using the provided encoder.
    CHIP_ERROR ReadThreadMetrics(AttributeValueEncoder & encoder) const;

    /// Determines the feature map based on the DiagnosticsProvider support.
    BitFlags<SoftwareDiagnostics::Feature> GetFeatureMap() const
    {
        return BitFlags<SoftwareDiagnostics::Feature>().Set(SoftwareDiagnostics::Feature::kWatermarks,
                                                            mEnabledAttributes.enableCurrentWatermarks &&
                                                                DeviceLayer::GetDiagnosticDataProvider().SupportsWatermarks());
    }

    CHIP_ERROR ResetWatermarks() { return DeviceLayer::GetDiagnosticDataProvider().ResetWatermarks(); }

    /// Returns acceptable attributes for the given Diagnostics data provider:
    ///   - ALWAYS includes global attributes
    ///   - adds heap/watermark depending on feature flags and if the interface supports it.
    CHIP_ERROR Attributes(ReadOnlyBufferBuilder<DataModel::AttributeEntry> & builder);

    /// Determines what commands are supported
    CHIP_ERROR AcceptedCommands(ReadOnlyBufferBuilder<DataModel::AcceptedCommandEntry> & builder);

private:
    const SoftwareDiagnosticsEnabledAttributes mEnabledAttributes;
};

} // namespace Clusters
} // namespace app
} // namespace chip
