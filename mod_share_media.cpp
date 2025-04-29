#include <switch.h>
#include <sys/mman.h>
#include <fcntl.h>


//======================================== freeswitch module start ===============
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load);

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_shmed_shutdown);

extern "C"
{
SWITCH_MODULE_DEFINITION(mod_medhub, mod_shmed_load, mod_shmed_shutdown, nullptr);
};

const int BUFFER_SIZE = 4096;
static const char *const STR = "Hello, Shared Media!";
void* shm_ptr = nullptr;

/**
 *  定义load函数，加载时运行
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load) {
    switch_api_interface_t *api_interface = nullptr;
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed load starting\n");

    // 创建共享内存
    int shm_fd = shm_open("/media_shm", O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, BUFFER_SIZE); // BUFFER_SIZE 为共享内存大小
    shm_ptr = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    memcpy(shm_ptr, STR, strlen(STR));
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed loaded\n");

    return SWITCH_STATUS_SUCCESS;
}

/**
 *  定义shutdown函数，关闭时运行
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_medhub_shutdown) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed shutdown called\n");

    // 清理
    munmap(shm_ptr, BUFFER_SIZE);
    shm_unlink("/media_shm");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed unload\n");
    return SWITCH_STATUS_SUCCESS;
}