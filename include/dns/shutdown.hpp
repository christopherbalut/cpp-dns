#pragma once

namespace dns
{
void install_shutdown_signal_handlers();
bool shutdown_requested();
} // namespace dns
