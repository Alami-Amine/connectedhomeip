// DO NOT EDIT MANUALLY - Generated file
//
// Identifier constant values for cluster WebRTCTransportRequestor (cluster code: 1364/0x554)
// based on src/controller/data_model/controller-clusters.matter
#pragma once

#include <lib/core/DataModelTypes.h>

namespace chip {
namespace app {
namespace Clusters {
namespace WebRTCTransportRequestor {
namespace Commands {

// Total number of client to server commands supported by the cluster
inline constexpr uint32_t kAcceptedCommandsCount = 4;

// Total number of server to client commands supported by the cluster (response commands)
inline constexpr uint32_t kGeneratedCommandsCount = 0;

namespace Offer {
inline constexpr CommandId Id = 0x00000000;
} // namespace Offer

namespace Answer {
inline constexpr CommandId Id = 0x00000001;
} // namespace Answer

namespace ICECandidates {
inline constexpr CommandId Id = 0x00000002;
} // namespace ICECandidates

namespace End {
inline constexpr CommandId Id = 0x00000003;
} // namespace End

} // namespace Commands
} // namespace WebRTCTransportRequestor
} // namespace Clusters
} // namespace app
} // namespace chip
