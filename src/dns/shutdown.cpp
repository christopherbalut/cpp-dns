#include "dns/shutdown.hpp"

#include <csignal>

namespace dns
{
namespace
{

volatile std::sig_atomic_t shutdown_requested_flag{0}; // volatile: read from memory, don't optimize

void handle_shutdown_signal(int /*signal*/) // signal commented out so we don't get compiler warning
{
    shutdown_requested_flag = 1;
}

} // namespace

void install_shutdown_signal_handlers()
{
    std::signal(SIGINT, handle_shutdown_signal);  // sigint: ctrl + C
    std::signal(SIGTERM, handle_shutdown_signal); // sigterm: sudo systemctl stop cpp-dns
}

bool shutdown_requested() // wrapper function
{
    return shutdown_requested_flag != 0;
}

} // namespace dns
