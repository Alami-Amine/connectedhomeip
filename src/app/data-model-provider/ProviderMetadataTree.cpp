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

#include <app/data-model-provider/ProviderMetadataTree.h>

#include <app/data-model-provider/MetadataList.h>

namespace chip {
namespace app {
namespace DataModel {

ReadOnlyBuffer<EndpointEntry> ProviderMetadataTree::EndpointsIgnoreError()
{

    ListBuilder<EndpointEntry> builder;
    (void) Endpoints(builder);
    return builder.TakeBuffer();
}

ReadOnlyBuffer<ServerClusterEntry> ProviderMetadataTree::ServerClustersIgnoreError(EndpointId endpointId)
{

    ListBuilder<ServerClusterEntry> builder;
    (void) ServerClusters(endpointId, builder);
    return builder.TakeBuffer();
}

ReadOnlyBuffer<AttributeEntry> ProviderMetadataTree::AttributesIgnoreError(const ConcreteClusterPath & path)
{
    ListBuilder<AttributeEntry> builder;
    (void) Attributes(path, builder);
    return builder.TakeBuffer();
}

} // namespace DataModel
} // namespace app
} // namespace chip