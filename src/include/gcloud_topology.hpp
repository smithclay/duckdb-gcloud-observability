#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! One canonical directed service edge decoded from App Topology's protobuf response.
struct GcloudServiceDependency {
	string source_service;
	string target_service;
	string source_type;
	string target_type;
	string edge_type;
	string environment;
	string source_attributes;
	string target_attributes;
	string edge_attributes;
};

//! Build GenerateDiscoveredResourcesTopologyRequest for the SRE service traffic graph:
//! Base/DiscoveredService --Observability/SENDS_TRAFFIC--> Base/DiscoveredService.
string BuildGcloudServiceDependenciesRequest(const string &project);

//! Decode a GenerateDiscoveredResourcesTopologyResponse into canonical directed service edges.
vector<GcloudServiceDependency> ParseGcloudServiceDependenciesResponse(const string &protobuf);

} // namespace duckdb
