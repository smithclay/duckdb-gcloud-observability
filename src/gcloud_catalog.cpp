#include "gcloud_catalog.hpp"

#include "alerts_table.hpp"
#include "gcloud_secret.hpp"
#include "logs_table.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/column_definition.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/storage/database_size.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/storage/table_storage_info.hpp"
#include "duckdb/transaction/transaction.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

namespace duckdb {
namespace {

[[noreturn]] static void ThrowReadOnly() {
	throw BinderException("gcloud catalogs are read-only");
}

//! Everything an ATTACH resolved, carried down to each table entry. The secret is stored by name
//! (not by value) so the credentials are re-resolved at every table bind, matching how the sibling
//! extensions handle secret replacement.
struct GcloudAttachOptions {
	string secret_name;
	//! Project for every table in the attachment. Empty means "fall back to the secret, then ADC",
	//! resolved per table bind rather than pinned here.
	string project;
	GcloudLogsSettings logs;
	GcloudAlertsSettings alerts;
};

//===--------------------------------------------------------------------===//
// Table entries
//===--------------------------------------------------------------------===//

//! Boilerplate shared by all three tables: they are read-only, carry no statistics, and differ only
//! in their schema and the scan they bind.
class GcloudTableEntry : public TableCatalogEntry {
public:
	GcloudTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const string &name,
	                 const GcloudAttachOptions &options, void (*get_schema)(vector<LogicalType> &, vector<string> &))
	    : GcloudTableEntry(catalog, schema, options, CreateInfo(schema, name, get_schema)) {
	}

	unique_ptr<BaseStatistics> GetStatistics(ClientContext &, column_t) override {
		return nullptr;
	}

	TableStorageInfo GetStorageInfo(ClientContext &) override {
		return TableStorageInfo();
	}

protected:
	GcloudAttachOptions options;

private:
	// DuckDB's TableCatalogEntry takes `CreateTableInfo &`, which a temporary cannot bind to; this
	// by-value delegating constructor gives it a named lvalue.
	GcloudTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const GcloudAttachOptions &options,
	                 CreateTableInfo info)
	    : TableCatalogEntry(catalog, schema, info), options(options) {
	}

	static CreateTableInfo CreateInfo(SchemaCatalogEntry &schema, const string &name,
	                                  void (*get_schema)(vector<LogicalType> &, vector<string> &)) {
		CreateTableInfo info(schema, name);
		vector<LogicalType> types;
		vector<string> names;
		get_schema(types, names);
		for (idx_t i = 0; i < names.size(); i++) {
			info.columns.AddColumn(ColumnDefinition(names[i], types[i]));
		}
		return info;
	}
};

class GcloudLogsTableEntry : public GcloudTableEntry {
public:
	GcloudLogsTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const GcloudAttachOptions &options)
	    : GcloudTableEntry(catalog, schema, "entries", options, GetGcloudLogsSchema) {
	}

	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
		return GetGcloudLogsTableScan(context, *this, options.secret_name, options.project, options.logs, bind_data);
	}
};

class GcloudOpenAlertsTableEntry : public GcloudTableEntry {
public:
	GcloudOpenAlertsTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const GcloudAttachOptions &options)
	    : GcloudTableEntry(catalog, schema, "open", options, GetGcloudOpenAlertsSchema) {
	}

	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
		return GetGcloudOpenAlertsTableScan(context, *this, options.secret_name, options.alerts, bind_data);
	}
};

class GcloudAlertPoliciesTableEntry : public GcloudTableEntry {
public:
	GcloudAlertPoliciesTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, const GcloudAttachOptions &options)
	    : GcloudTableEntry(catalog, schema, "policies", options, GetGcloudAlertPoliciesSchema) {
	}

	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
		return GetGcloudAlertPoliciesTableScan(context, *this, options.secret_name, options.alerts, bind_data);
	}
};

//===--------------------------------------------------------------------===//
// Schemas
//===--------------------------------------------------------------------===//

//! A read-only schema holding a fixed set of tables. Every mutating entry point throws.
class GcloudSchemaEntry : public SchemaCatalogEntry {
public:
	GcloudSchemaEntry(Catalog &catalog, const string &name) : GcloudSchemaEntry(catalog, CreateInfo(name)) {
	}

	void Scan(ClientContext &, CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
		Scan(type, callback);
	}

	void Scan(CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
		if (type != CatalogType::TABLE_ENTRY) {
			return;
		}
		for (auto &table : tables) {
			callback(*table);
		}
	}

	optional_ptr<CatalogEntry> LookupEntry(CatalogTransaction, const EntryLookupInfo &lookup_info) override {
		if (lookup_info.GetCatalogType() != CatalogType::TABLE_ENTRY) {
			return nullptr;
		}
		for (auto &table : tables) {
			if (StringUtil::CIEquals(table->name, lookup_info.GetEntryName())) {
				return table.get();
			}
		}
		return nullptr;
	}

	optional_ptr<CatalogEntry> CreateIndex(CatalogTransaction, CreateIndexInfo &, TableCatalogEntry &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateFunction(CatalogTransaction, CreateFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateTable(CatalogTransaction, BoundCreateTableInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateView(CatalogTransaction, CreateViewInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateSequence(CatalogTransaction, CreateSequenceInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateTableFunction(CatalogTransaction, CreateTableFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCopyFunction(CatalogTransaction, CreateCopyFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreatePragmaFunction(CatalogTransaction, CreatePragmaFunctionInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCollation(CatalogTransaction, CreateCollationInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateCoordinateSystem(CatalogTransaction, CreateCoordinateSystemInfo &) override {
		ThrowReadOnly();
	}
	optional_ptr<CatalogEntry> CreateType(CatalogTransaction, CreateTypeInfo &) override {
		ThrowReadOnly();
	}
	void DropEntry(ClientContext &, DropInfo &) override {
		ThrowReadOnly();
	}
	void Alter(CatalogTransaction, AlterInfo &) override {
		ThrowReadOnly();
	}

	//! Populated by the catalog immediately after construction; the schema owns its tables.
	void AddTable(unique_ptr<TableCatalogEntry> table) {
		tables.push_back(std::move(table));
	}

protected:
	vector<unique_ptr<TableCatalogEntry>> tables;

private:
	//! Same lvalue dance as GcloudTableEntry: SchemaCatalogEntry takes `CreateSchemaInfo &`.
	GcloudSchemaEntry(Catalog &catalog, CreateSchemaInfo info) : SchemaCatalogEntry(catalog, info) {
	}

	static CreateSchemaInfo CreateInfo(const string &name) {
		CreateSchemaInfo info;
		info.schema = name;
		return info;
	}
};

//===--------------------------------------------------------------------===//
// Catalog
//===--------------------------------------------------------------------===//

class GcloudCatalog : public Catalog {
public:
	GcloudCatalog(AttachedDatabase &db, GcloudAttachOptions options)
	    : Catalog(db), logs_schema(make_uniq<GcloudSchemaEntry>(*this, "logs")),
	      alerts_schema(make_uniq<GcloudSchemaEntry>(*this, "alerts")) {
		logs_schema->AddTable(make_uniq<GcloudLogsTableEntry>(*this, *logs_schema, options));
		alerts_schema->AddTable(make_uniq<GcloudOpenAlertsTableEntry>(*this, *alerts_schema, options));
		alerts_schema->AddTable(make_uniq<GcloudAlertPoliciesTableEntry>(*this, *alerts_schema, options));
	}

	void Initialize(bool) override {
	}

	string GetCatalogType() override {
		return "gcloud";
	}

	optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction, CreateSchemaInfo &) override {
		ThrowReadOnly();
	}

	void ScanSchemas(ClientContext &, std::function<void(SchemaCatalogEntry &)> callback) override {
		callback(*logs_schema);
		callback(*alerts_schema);
	}

	optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction, const EntryLookupInfo &schema_lookup,
	                                              OnEntryNotFound if_not_found) override {
		if (StringUtil::CIEquals(schema_lookup.GetEntryName(), "logs")) {
			return logs_schema.get();
		}
		if (StringUtil::CIEquals(schema_lookup.GetEntryName(), "alerts")) {
			return alerts_schema.get();
		}
		if (if_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw CatalogException(schema_lookup.GetErrorContext(), "Schema with name %s does not exist!",
			                       schema_lookup.GetEntryName());
		}
		return nullptr;
	}

	PhysicalOperator &PlanCreateTableAs(ClientContext &, PhysicalPlanGenerator &, LogicalCreateTable &,
	                                    PhysicalOperator &) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanInsert(ClientContext &, PhysicalPlanGenerator &, LogicalInsert &,
	                             optional_ptr<PhysicalOperator>) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanDelete(ClientContext &, PhysicalPlanGenerator &, LogicalDelete &,
	                             PhysicalOperator &) override {
		ThrowReadOnly();
	}
	PhysicalOperator &PlanUpdate(ClientContext &, PhysicalPlanGenerator &, LogicalUpdate &,
	                             PhysicalOperator &) override {
		ThrowReadOnly();
	}

	DatabaseSize GetDatabaseSize(ClientContext &) override {
		return DatabaseSize();
	}
	bool InMemory() override {
		return false;
	}
	string GetDBPath() override {
		return "gcloud:";
	}

private:
	void DropSchema(ClientContext &, DropInfo &) override {
		ThrowReadOnly();
	}

	unique_ptr<GcloudSchemaEntry> logs_schema;
	unique_ptr<GcloudSchemaEntry> alerts_schema;
};

class GcloudTransaction : public Transaction {
public:
	GcloudTransaction(TransactionManager &manager, ClientContext &context) : Transaction(manager, context) {
	}

	void SetReadWrite() override {
		ThrowReadOnly();
	}

	void SetModifications(DatabaseModificationType) override {
		ThrowReadOnly();
	}
};

class GcloudTransactionManager : public TransactionManager {
public:
	explicit GcloudTransactionManager(AttachedDatabase &db) : TransactionManager(db) {
	}

	Transaction &StartTransaction(ClientContext &context) override {
		auto transaction = make_uniq<GcloudTransaction>(*this, context);
		auto result = transaction.get();
		lock_guard<mutex> guard(transaction_lock);
		transactions.emplace(result, std::move(transaction));
		return *result;
	}

	ErrorData CommitTransaction(ClientContext &, Transaction &transaction) override {
		lock_guard<mutex> guard(transaction_lock);
		transactions.erase(&transaction);
		return ErrorData();
	}

	void RollbackTransaction(Transaction &transaction) override {
		lock_guard<mutex> guard(transaction_lock);
		transactions.erase(&transaction);
	}

	void Checkpoint(ClientContext &, bool) override {
	}

private:
	mutex transaction_lock;
	unordered_map<Transaction *, unique_ptr<Transaction>> transactions;
};

//===--------------------------------------------------------------------===//
// ATTACH
//===--------------------------------------------------------------------===//

static string ParseAttachString(const string &option_name, const Value &value) {
	if (value.IsNull() || value.type().id() != LogicalTypeId::VARCHAR) {
		throw InvalidInputException("gcloud ATTACH option %s must be a non-null VARCHAR", option_name);
	}
	return value.GetValue<string>();
}

static int64_t ParseAttachInteger(const string &option_name, const Value &value) {
	if (value.IsNull() || !value.type().IsIntegral()) {
		throw InvalidInputException("gcloud ATTACH option %s must be a non-null integer", option_name);
	}
	return value.GetValue<int64_t>();
}

static unique_ptr<Catalog> AttachGcloud(optional_ptr<StorageExtensionInfo>, ClientContext &context,
                                        AttachedDatabase &db, const string &, AttachInfo &info,
                                        AttachOptions &options) {
	if (info.path != "gcloud:") {
		throw InvalidInputException("gcloud catalogs must be attached from the path 'gcloud:'");
	}

	GcloudAttachOptions attach;
	for (const auto &option : options.options) {
		auto key = StringUtil::Lower(option.first);
		if (key == "secret") {
			attach.secret_name = ParseAttachString("SECRET", option.second);
			if (attach.secret_name.empty()) {
				throw InvalidInputException("gcloud ATTACH option SECRET must not be empty");
			}
		} else if (key == "project") {
			attach.project = ParseAttachString("PROJECT", option.second);
		} else if (key == "filter") {
			attach.logs.filter = ParseAttachString("FILTER", option.second);
		} else if (key == "start_time") {
			attach.logs.start_time = ParseAttachString("START_TIME", option.second);
		} else if (key == "end_time") {
			attach.logs.end_time = ParseAttachString("END_TIME", option.second);
		} else if (key == "order_by") {
			attach.logs.order_by = ParseAttachString("ORDER_BY", option.second);
		} else if (key == "page_size") {
			attach.logs.page_size = ParseAttachInteger("PAGE_SIZE", option.second);
		} else if (key == "max_rows") {
			attach.logs.max_rows = ParseAttachInteger("MAX_ROWS", option.second);
		} else if (key == "retries") {
			attach.logs.retries = ParseAttachInteger("RETRIES", option.second);
		} else if (key == "timeout") {
			attach.logs.timeout_seconds = ParseAttachInteger("TIMEOUT", option.second);
		} else {
			throw InvalidInputException("Unsupported gcloud ATTACH option '%s'; supported options are SECRET, PROJECT, "
			                            "FILTER, START_TIME, END_TIME, ORDER_BY, PAGE_SIZE, MAX_ROWS, RETRIES, and "
			                            "TIMEOUT",
			                            option.first);
		}
	}
	ValidateGcloudLogsSettings(attach.logs, "gcloud ATTACH");

	// The alert tables share the attachment's retry/timeout budget and row cap, but keep their own
	// page size: the Monitoring listings are far smaller than a log window, and 1000 is not a valid
	// page size there.
	attach.alerts.max_rows = attach.logs.max_rows;
	attach.alerts.retries = attach.logs.retries;
	attach.alerts.timeout_seconds = attach.logs.timeout_seconds;

	// Resolve the secret once at attach time so a bad name fails here rather than at first query.
	// Only its name is retained, so a later CREATE OR REPLACE SECRET is picked up.
	GetGcloudCredentials(context, attach.secret_name);
	attach.alerts.project = attach.project;

	db.SetReadOnlyDatabase();
	return make_uniq<GcloudCatalog>(db, std::move(attach));
}

static unique_ptr<TransactionManager> CreateGcloudTransactionManager(optional_ptr<StorageExtensionInfo>,
                                                                     AttachedDatabase &db, Catalog &) {
	return make_uniq<GcloudTransactionManager>(db);
}

} // namespace

void RegisterGcloudCatalog(ExtensionLoader &loader) {
	auto storage = make_shared_ptr<StorageExtension>();
	storage->attach = AttachGcloud;
	storage->create_transaction_manager = CreateGcloudTransactionManager;
	StorageExtension::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()), "gcloud", std::move(storage));
}

} // namespace duckdb
