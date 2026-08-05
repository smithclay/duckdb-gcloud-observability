#include "gcloud_topology.hpp"

#include "gcloud_yyjson.hpp"

#include "duckdb/common/exception.hpp"

#include <cstring>
#include <unordered_map>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {
namespace {

//! App Topology is currently a protobuf-only Preview API. These helpers implement only the small
//! protobuf subset used by its topology request/response, avoiding generated clients and a scan of
//! the underlying Cloud Trace spans.
static void PutVarint(string &out, uint64_t value) {
	while (value >= 0x80) {
		out.push_back(static_cast<char>((value & 0x7f) | 0x80));
		value >>= 7;
	}
	out.push_back(static_cast<char>(value));
}

static void PutTag(string &out, uint32_t field, uint32_t wire_type) {
	PutVarint(out, (static_cast<uint64_t>(field) << 3) | wire_type);
}

static void PutBytes(string &out, uint32_t field, const string &value) {
	PutTag(out, field, 2);
	PutVarint(out, value.size());
	out.append(value);
}

static void PutEnum(string &out, uint32_t field, uint64_t value) {
	PutTag(out, field, 0);
	PutVarint(out, value);
}

struct ProtoField {
	uint32_t number = 0;
	uint32_t wire_type = 0;
	const_data_ptr_t data = nullptr;
	idx_t size = 0;
	uint64_t integer = 0;
};

class ProtoReader {
public:
	explicit ProtoReader(const string &value)
	    : cursor(reinterpret_cast<const_data_ptr_t>(value.data())), end(cursor + value.size()) {
	}
	ProtoReader(const_data_ptr_t data, idx_t size) : cursor(data), end(data + size) {
	}

	bool Next(ProtoField &field) {
		if (cursor == end) {
			return false;
		}
		auto tag = ReadVarint();
		field.number = static_cast<uint32_t>(tag >> 3);
		field.wire_type = static_cast<uint32_t>(tag & 7);
		field.data = nullptr;
		field.size = 0;
		field.integer = 0;
		if (field.number == 0) {
			ThrowMalformed();
		}
		switch (field.wire_type) {
		case 0:
			field.integer = ReadVarint();
			break;
		case 1:
			field.data = Take(8);
			field.size = 8;
			break;
		case 2: {
			auto size = ReadVarint();
			if (size > static_cast<uint64_t>(end - cursor)) {
				ThrowMalformed();
			}
			field.data = Take(static_cast<idx_t>(size));
			field.size = static_cast<idx_t>(size);
			break;
		}
		case 5:
			field.data = Take(4);
			field.size = 4;
			break;
		default:
			ThrowMalformed();
		}
		return true;
	}

private:
	const_data_ptr_t cursor;
	const_data_ptr_t end;

	[[noreturn]] static void ThrowMalformed() {
		throw IOException("App Topology API returned a malformed protobuf response");
	}

	const_data_ptr_t Take(idx_t count) {
		if (count > static_cast<idx_t>(end - cursor)) {
			ThrowMalformed();
		}
		auto result = cursor;
		cursor += count;
		return result;
	}

	uint64_t ReadVarint() {
		uint64_t value = 0;
		for (uint32_t shift = 0; shift < 64; shift += 7) {
			if (cursor == end) {
				ThrowMalformed();
			}
			auto byte = *cursor++;
			value |= static_cast<uint64_t>(byte & 0x7f) << shift;
			if (!(byte & 0x80)) {
				return value;
			}
		}
		ThrowMalformed();
	}
};

static string FieldString(const ProtoField &field) {
	return string(reinterpret_cast<const char *>(field.data), field.size);
}

enum class JsonKind { NIL, BOOLEAN, NUMBER, STRING, OBJECT, ARRAY };

struct ProtoJsonValue {
	JsonKind kind = JsonKind::NIL;
	bool boolean = false;
	double number = 0;
	string text;
	vector<pair<string, ProtoJsonValue>> object;
	vector<ProtoJsonValue> array;
};

static ProtoJsonValue ParseProtoValue(const_data_ptr_t data, idx_t size);

static vector<pair<string, ProtoJsonValue>> ParseProtoStruct(const_data_ptr_t data, idx_t size) {
	vector<pair<string, ProtoJsonValue>> result;
	ProtoReader reader(data, size);
	ProtoField field;
	while (reader.Next(field)) {
		if (field.number != 1 || field.wire_type != 2) {
			continue;
		}
		string key;
		ProtoJsonValue value;
		ProtoReader entry(field.data, field.size);
		ProtoField entry_field;
		while (entry.Next(entry_field)) {
			if (entry_field.number == 1 && entry_field.wire_type == 2) {
				key = FieldString(entry_field);
			} else if (entry_field.number == 2 && entry_field.wire_type == 2) {
				value = ParseProtoValue(entry_field.data, entry_field.size);
			}
		}
		if (!key.empty()) {
			result.emplace_back(std::move(key), std::move(value));
		}
	}
	return result;
}

static ProtoJsonValue ParseProtoValue(const_data_ptr_t data, idx_t size) {
	ProtoJsonValue result;
	ProtoReader reader(data, size);
	ProtoField field;
	while (reader.Next(field)) {
		switch (field.number) {
		case 1: // null_value
			result.kind = JsonKind::NIL;
			break;
		case 2: // number_value
			if (field.wire_type == 1) {
				uint64_t bits = 0;
				for (idx_t i = 0; i < 8; i++) {
					bits |= static_cast<uint64_t>(field.data[i]) << (8 * i);
				}
				static_assert(sizeof(bits) == sizeof(result.number), "double must be 64-bit");
				memcpy(&result.number, &bits, sizeof(bits));
				result.kind = JsonKind::NUMBER;
			}
			break;
		case 3: // string_value
			if (field.wire_type == 2) {
				result.kind = JsonKind::STRING;
				result.text = FieldString(field);
			}
			break;
		case 4: // bool_value
			if (field.wire_type == 0) {
				result.kind = JsonKind::BOOLEAN;
				result.boolean = field.integer != 0;
			}
			break;
		case 5: // struct_value
			if (field.wire_type == 2) {
				result.kind = JsonKind::OBJECT;
				result.object = ParseProtoStruct(field.data, field.size);
			}
			break;
		case 6: // list_value
			if (field.wire_type == 2) {
				result.kind = JsonKind::ARRAY;
				ProtoReader list(field.data, field.size);
				ProtoField item;
				while (list.Next(item)) {
					if (item.number == 1 && item.wire_type == 2) {
						result.array.push_back(ParseProtoValue(item.data, item.size));
					}
				}
			}
			break;
		default:
			break;
		}
	}
	return result;
}

static yyjson_mut_val *ToJson(YyjsonMutDocPtr &doc, const ProtoJsonValue &value) {
	switch (value.kind) {
	case JsonKind::BOOLEAN:
		return yyjson_mut_bool(doc.get(), value.boolean);
	case JsonKind::NUMBER:
		return yyjson_mut_real(doc.get(), value.number);
	case JsonKind::STRING:
		return yyjson_mut_strcpy(doc.get(), value.text.c_str());
	case JsonKind::OBJECT: {
		auto object = yyjson_mut_obj(doc.get());
		for (const auto &entry : value.object) {
			yyjson_mut_obj_add(object, yyjson_mut_strcpy(doc.get(), entry.first.c_str()), ToJson(doc, entry.second));
		}
		return object;
	}
	case JsonKind::ARRAY: {
		auto array = yyjson_mut_arr(doc.get());
		for (const auto &item : value.array) {
			yyjson_mut_arr_append(array, ToJson(doc, item));
		}
		return array;
	}
	case JsonKind::NIL:
	default:
		return yyjson_mut_null(doc.get());
	}
}

static string FindStringProperty(const vector<pair<string, ProtoJsonValue>> &properties,
                                 std::initializer_list<const char *> keys) {
	for (const char *key : keys) {
		for (const auto &property : properties) {
			if (property.first == key && property.second.kind == JsonKind::STRING) {
				return property.second.text;
			}
		}
	}
	return string();
}

static string AttributesJson(const vector<pair<string, ProtoJsonValue>> &properties, const string &id,
                             const vector<string> &labels) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	if (!id.empty()) {
		GcloudPutStr(doc.get(), root, "_app_topology_id", id.c_str());
	}
	if (!labels.empty()) {
		auto array = yyjson_mut_arr(doc.get());
		for (const auto &label : labels) {
			yyjson_mut_arr_append(array, yyjson_mut_strcpy(doc.get(), label.c_str()));
		}
		yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc.get(), "_app_topology_labels"), array);
	}
	for (const auto &property : properties) {
		yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc.get(), property.first.c_str()), ToJson(doc, property.second));
	}
	return GcloudWriteIfAny(doc.get(), root);
}

struct TopologyNode {
	string id;
	vector<string> labels;
	vector<pair<string, ProtoJsonValue>> properties;
	string service_name;
	string type;
	string environment;
	string attributes;
};

struct TopologyEdge {
	string source_id;
	string target_id;
	string type;
	vector<string> labels;
	vector<pair<string, ProtoJsonValue>> properties;
	string attributes;
};

static string LastResourceSegment(const string &id) {
	auto slash = id.find_last_of('/');
	auto colon = id.find_last_of(':');
	auto separator = MaxValue<idx_t>(slash == string::npos ? 0 : slash + 1, colon == string::npos ? 0 : colon + 1);
	return separator < id.size() ? id.substr(separator) : id;
}

static string ConcreteType(const vector<string> &labels, const string &resource_type) {
	for (auto it = labels.rbegin(); it != labels.rend(); ++it) {
		if (*it == "Base/Resource" || *it == "Base/DiscoveredService") {
			continue;
		}
		return it->rfind("Base/", 0) == 0 ? it->substr(5) : *it;
	}
	return resource_type;
}

static TopologyNode ParseNode(const ProtoField &node_field) {
	TopologyNode node;
	ProtoReader reader(node_field.data, node_field.size);
	ProtoField field;
	while (reader.Next(field)) {
		if (field.wire_type != 2) {
			continue;
		}
		if (field.number == 3) {
			node.properties = ParseProtoStruct(field.data, field.size);
		} else if (field.number == 4) {
			node.id = FieldString(field);
		} else if (field.number == 5) {
			node.labels.push_back(FieldString(field));
		}
	}
	node.service_name = FindStringProperty(node.properties, {"Base/displayName", "displayName", "name"});
	if (node.service_name.empty()) {
		node.service_name = LastResourceSegment(node.id);
	}
	auto resource_type = FindStringProperty(node.properties, {"Base/resourceType", "resourceType"});
	node.type = ConcreteType(node.labels, resource_type);
	node.environment = FindStringProperty(node.properties, {"Base/environment", "environment"});
	node.attributes = AttributesJson(node.properties, node.id, node.labels);
	return node;
}

static TopologyEdge ParseEdge(const ProtoField &edge_field) {
	TopologyEdge edge;
	ProtoReader reader(edge_field.data, edge_field.size);
	ProtoField field;
	while (reader.Next(field)) {
		if (field.wire_type != 2) {
			continue;
		}
		if (field.number == 5) {
			edge.properties = ParseProtoStruct(field.data, field.size);
		} else if (field.number == 6) {
			edge.source_id = FieldString(field);
		} else if (field.number == 7) {
			edge.target_id = FieldString(field);
		} else if (field.number == 8) {
			edge.type = FieldString(field);
		} else if (field.number == 9) {
			ProtoReader label(field.data, field.size);
			ProtoField label_field;
			while (label.Next(label_field)) {
				if (label_field.number == 1 && label_field.wire_type == 2) {
					edge.labels.push_back(FieldString(label_field));
				}
			}
		}
	}
	edge.attributes = AttributesJson(edge.properties, string(), edge.labels);
	return edge;
}

static string DisplayEdgeType(const string &type) {
	return type == "Observability/SENDS_TRAFFIC" ? "sends traffic to" : type;
}

} // namespace

string BuildGcloudServiceDependenciesRequest(const string &project) {
	// LabelPropertiesPattern.matcher_expression = "Base/DiscoveredService"
	string service_label;
	PutBytes(service_label, 1, "Base/DiscoveredService");
	// NodePattern.label_properties_pattern = service_label
	string service_node;
	PutBytes(service_node, 3, service_label);

	// EdgePattern.direction = OUTGOING; label_properties_pattern = SENDS_TRAFFIC.
	string traffic_label;
	PutBytes(traffic_label, 1, "Observability/SENDS_TRAFFIC");
	string traffic_edge;
	PutEnum(traffic_edge, 1, 1);
	PutBytes(traffic_edge, 2, traffic_label);

	// A filter is the edge followed by the target graph pattern.
	string target_pattern;
	PutBytes(target_pattern, 1, service_node);
	string filter;
	PutBytes(filter, 1, traffic_edge);
	PutBytes(filter, 2, target_pattern);

	string graph_pattern;
	PutBytes(graph_pattern, 1, service_node);
	PutBytes(graph_pattern, 2, filter);

	auto location = "projects/" + project + "/locations/global";
	string request;
	PutBytes(request, 1, location + "/discoveredResourcesTopology");
	PutBytes(request, 2, location + "/domains/SRE");
	PutBytes(request, 3, graph_pattern);
	return request;
}

vector<GcloudServiceDependency> ParseGcloudServiceDependenciesResponse(const string &protobuf) {
	vector<TopologyNode> nodes;
	vector<TopologyEdge> edges;
	ProtoReader response(protobuf);
	ProtoField response_field;
	while (response.Next(response_field)) {
		if (response_field.number != 1 || response_field.wire_type != 2) {
			continue;
		}
		ProtoReader topology(response_field.data, response_field.size);
		ProtoField topology_field;
		while (topology.Next(topology_field)) {
			if (topology_field.wire_type != 2) {
				continue;
			}
			if (topology_field.number == 1) {
				nodes.push_back(ParseNode(topology_field));
			} else if (topology_field.number == 2) {
				edges.push_back(ParseEdge(topology_field));
			}
		}
	}

	unordered_map<string, idx_t> node_by_id;
	for (idx_t i = 0; i < nodes.size(); i++) {
		if (!nodes[i].id.empty()) {
			node_by_id[nodes[i].id] = i;
		}
	}

	vector<GcloudServiceDependency> result;
	result.reserve(edges.size());
	for (auto &edge : edges) {
		GcloudServiceDependency dependency;
		auto source = node_by_id.find(edge.source_id);
		auto target = node_by_id.find(edge.target_id);
		if (source != node_by_id.end()) {
			auto &node = nodes[source->second];
			dependency.source_service = node.service_name;
			dependency.source_type = node.type;
			dependency.environment = node.environment;
			dependency.source_attributes = node.attributes;
		} else {
			dependency.source_service = LastResourceSegment(edge.source_id);
		}
		if (target != node_by_id.end()) {
			auto &node = nodes[target->second];
			dependency.target_service = node.service_name;
			dependency.target_type = node.type;
			if (dependency.environment.empty()) {
				dependency.environment = node.environment;
			}
			dependency.target_attributes = node.attributes;
		} else {
			dependency.target_service = LastResourceSegment(edge.target_id);
		}
		dependency.edge_type = DisplayEdgeType(edge.type);
		dependency.edge_attributes = edge.attributes;
		result.push_back(std::move(dependency));
	}
	return result;
}

} // namespace duckdb
