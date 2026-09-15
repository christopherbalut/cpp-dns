#include "dns/query_logger.hpp"

namespace dns
{

void NoopQueryLogger::log_query(const QueryLogEntry& /*entry*/) {}

} // namespace dns
