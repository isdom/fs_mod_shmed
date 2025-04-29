#include <switch.h>


//======================================== freeswitch module start ===============
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load);

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_shmed_shutdown);

extern "C"
{
SWITCH_MODULE_DEFINITION(mod_medhub, mod_shmed_load, mod_shmed_shutdown, nullptr);
};



/**
 *  定义load函数，加载时运行
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load) {
    switch_api_interface_t *api_interface = nullptr;
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed load starting\n");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed loaded\n");

    return SWITCH_STATUS_SUCCESS;
}

/**
 *  定义shutdown函数，关闭时运行
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_medhub_shutdown) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed shutdown called\n");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed unload\n");
    return SWITCH_STATUS_SUCCESS;
}