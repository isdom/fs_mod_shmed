#include <switch.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

const int BLOCK_SIZE = 512;
const int BLOCK_COUNT = 1024 * 1024;
int shm_fd;
uint8_t* shm_ptr = nullptr;
switch_mutex_t *shm_mutex = nullptr;
int next_block_idx = 0;

//======================================== freeswitch module start ===============
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load);

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_shmed_shutdown);

extern "C"
{
SWITCH_MODULE_DEFINITION(mod_shmed, mod_shmed_load, mod_shmed_shutdown, nullptr);
};

int shmed_alloc_block(const uint16_t len, switch_channel_t *channel) {
    int block_idx = 0;
    int try_cnt = 0;
    switch_mutex_lock(shm_mutex);
    while (try_cnt < BLOCK_COUNT - 1) {
        uint8_t *current = shm_ptr + (next_block_idx + 1) * BLOCK_SIZE;
        uint16_t data_size = (uint16_t)((current[1] << 8) | current[0]);
        if (data_size == 0) {
            // set len to block's first 2 bytes as little ending
            current[0] = len & 0xff;
            current[1] = (len & 0xff00) >> 8;
            // clear local idx field (int32_t)
            current[2] = 0x00;
            current[3] = 0x00;
            current[4] = 0x00;
            current[5] = 0x00;
            block_idx = next_block_idx + 1;
            next_block_idx = (next_block_idx + 1) % (BLOCK_COUNT - 1);
            goto unlock;
        } else {
            try_cnt++;
            next_block_idx = (next_block_idx + 1) % (BLOCK_COUNT - 1);
        }
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: shmed_alloc_block no valid block, try %d times!\n",
                      switch_channel_get_uuid(channel), try_cnt);
unlock:
    switch_mutex_unlock(shm_mutex);
    return block_idx;
}

void update_block_idx(int block_idx) {
    switch_mutex_lock(shm_mutex);
    if (block_idx == next_block_idx) { // TODO
        memcpy(shm_ptr, &block_idx, sizeof(int));
    }
    switch_mutex_unlock(shm_mutex);
}

typedef struct {
    int32_t  local_idx;
    switch_core_session_t *session;
    switch_media_bug_t *bug;
} shmed_bug_t;

static switch_bool_t handle_read_media_bug(switch_media_bug_t *bug, shmed_bug_t *pvt, switch_channel_t *channel) {
    uint8_t data[SWITCH_RECOMMENDED_BUFFER_SIZE];
    switch_frame_t frame = {nullptr};
    frame.data = data;
    frame.buflen = sizeof(data);
    if (switch_core_media_bug_read(bug, &frame, SWITCH_FALSE) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: handle_read_media_bug => switch_core_media_bug_read failed, ignore!\n",
                          switch_channel_get_uuid(channel));
        return SWITCH_TRUE;
    } else {
        /*
         +---------------+---------------+---------------+---------------+---------------+-...-+---------------+
         |  Length: 2B   | LocalIdx:4B   |        Timestamp (8B)         |        Payload (N Bytes)            |
         |  (uint16_t)   |  (int32_t)    |        (int64_t, μs)          |        (variable length)            |
         +---------------+---------------+-------+-------+-------+-------+---------------+-...-+---------------+
                 |                |               |               |               |               |
                 |                |               |               |               |               |
                 v                v               v               v               v               v
            [0x00 0x1F]      [0x7F]    [0x00 0x00 0x01 0x8A 0x01 0x8B 0x23 0x45]  [0x48 0x65 0x6C 0x6C 0x6F]
            (Length=31)     (Ready)         (Timestamp: 100000 μs)                  ("Hello" in ASCII)
        */

        switch_time_t now_tm = switch_micro_time_now();
        uint16_t size = (uint16_t)(4 + sizeof(switch_time_t) /* timestamp: 8 bytes */ + frame.datalen);
        if (size > BLOCK_SIZE - 2) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: handle_read_media_bug => frame.datalen:%d exceed block size, ignore!\n",
                              switch_channel_get_uuid(channel), size);
            return SWITCH_TRUE;
        }

        int block_idx = shmed_alloc_block(size, channel);
        if (block_idx > 0) {
            //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[%s]: store frame %d bytes to block [%d]\n",
            //                  switch_channel_get_uuid(channel), frame.datalen, block_idx);
            uint8_t *data_ptr = shm_ptr + block_idx * BLOCK_SIZE + 2; // skip 2 bytes for size
            memcpy(data_ptr + sizeof(int32_t), &now_tm, sizeof(switch_time_t));
            memcpy(data_ptr + sizeof(int32_t) + sizeof(switch_time_t), frame.data, frame.datalen);
            // set local idx for block
            memcpy(data_ptr, &pvt->local_idx, sizeof(int32_t));

            // update newest block id to notify peer
            update_block_idx(block_idx);
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: no valid block, drop frame %d bytes\n",
                              switch_channel_get_uuid(channel), frame.datalen);
        }
    }
    return SWITCH_TRUE;
}

static switch_bool_t handle_close_media_bug(shmed_bug_t *pvt, switch_channel_t *channel) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[%s]: handle_close_media_bug\n", switch_channel_get_uuid(channel));
    return SWITCH_TRUE;
}

static switch_bool_t handle_init_media_bug(shmed_bug_t *pvt, switch_channel_t *channel) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[%s]: Share Media Init\n", switch_channel_get_uuid(channel));
    return SWITCH_TRUE;
}

/**
 * asr 回调处理
 *
 * @param bug
 * @param pvt
 * @param type
 * @return switch_bool_t
 */
static switch_bool_t share_media_bug_hook(switch_media_bug_t *bug, shmed_bug_t *pvt, switch_abc_type_t type) {
    switch_channel_t *channel = switch_core_session_get_channel(pvt->session);
    switch (type) {
        case SWITCH_ABC_TYPE_INIT:
            return handle_init_media_bug(pvt, channel);
        case SWITCH_ABC_TYPE_CLOSE:
            return handle_close_media_bug(pvt, channel);
        case SWITCH_ABC_TYPE_READ:
            return handle_read_media_bug(bug, pvt, channel);
        default:
            break;
    }
    return SWITCH_TRUE;
}

static switch_status_t shmed_on_exchange_media(switch_core_session_t *session) {
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    const char *str_idx = switch_channel_get_variable(channel, "local_idx");
    if (!str_idx) {
        // not found local_idx var for session
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                          "shmed_on_exchange_media: [%s] missing local_idx, ignore\n",
                          switch_core_session_get_uuid(session));
        return SWITCH_STATUS_SUCCESS;
    }

    auto pvt = (shmed_bug_t*)switch_core_session_alloc(session, sizeof(shmed_bug_t));
    pvt->local_idx = (int32_t)strtol(str_idx, nullptr, 10);
    pvt->session = session;

    // 对 session 添加 media bug
    if ((status = switch_core_media_bug_add(session, "shmed", nullptr,
                                            reinterpret_cast<switch_media_bug_callback_t>(share_media_bug_hook),
                                            pvt, 0,
                                            // SMBF_READ_REPLACE | SMBF_WRITE_REPLACE |  SMBF_NO_PAUSE | SMBF_ONE_ONLY,
                                            SMBF_READ_STREAM | SMBF_NO_PAUSE,
                                            &pvt->bug)) != SWITCH_STATUS_SUCCESS) {
        // SWITCH_ABC_TYPE_INIT 调用逻辑参考: https://github.com/signalwire/freeswitch/blob/79ce08810120b681992a3e666bcbe8d2ac2a7383/src/switch_core_media_bug.c#L956C18-L956C18
        // SWITCH_ABC_TYPE_READ 调用逻辑参考：https://github.com/signalwire/freeswitch/blob/79ce08810120b681992a3e666bcbe8d2ac2a7383/src/switch_core_io.c#L748
        // 如上述代码中所示，当 switch_media_bug_callback_t 返回值为：SWITCH_FALSE 时，该 media bug 都会被立即从 bug 链表中删除
        // 因此, 如果媒体处理出现异常，应该以及 在 media bug callback 中返回 SWITCH_FALSE
        return SWITCH_STATUS_SUCCESS;
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"[%s], shmed_on_exchange_media\n", switch_channel_get_name(channel));
    return SWITCH_STATUS_SUCCESS;
}

static void on_channel_progress_media(switch_event_t *event) {
    switch_event_header_t *hdr;
    const char *uuid;

    hdr = switch_event_get_header_ptr(event, "Unique-ID");
    uuid = hdr->value;
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "on_channel_progress_media: uuid: %s", uuid);

    switch_core_session *session  = switch_core_session_force_locate(uuid);
    if (!session) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "on_channel_progress_media: locate session [%s] failed, maybe ended\n",
                          uuid);
    } else {
        shmed_on_exchange_media(session);
        switch_core_session_rwunlock(session);
    }
}

switch_state_handler_table_t shmed_cs_handlers = {
        /*! executed when the state changes to init */
        // switch_state_handler_t on_init;
        nullptr,
        /*! executed when the state changes to routing */
        // switch_state_handler_t on_routing;
        nullptr,
        /*! executed when the state changes to execute */
        // switch_state_handler_t on_execute;
        nullptr,
        /*! executed when the state changes to hangup */
        // switch_state_handler_t on_hangup;
        nullptr,
        /*! executed when the state changes to exchange_media */
        // switch_state_handler_t on_exchange_media;
        shmed_on_exchange_media,
        /*! executed when the state changes to soft_execute */
        // switch_state_handler_t on_soft_execute;
        nullptr,
        /*! executed when the state changes to consume_media */
        // switch_state_handler_t on_consume_media;
        nullptr,
        /*! executed when the state changes to hibernate */
        // switch_state_handler_t on_hibernate;
        nullptr,
        /*! executed when the state changes to reset */
        // switch_state_handler_t on_reset;
        nullptr,
        /*! executed when the state changes to park */
        // switch_state_handler_t on_park;
        nullptr,
        /*! executed when the state changes to reporting */
        // switch_state_handler_t on_reporting;
        nullptr,
        /*! executed when the state changes to destroy */
        // switch_state_handler_t on_destroy;
        nullptr,
        // int flags;
        0
};

const size_t BUFFER_SIZE = BLOCK_SIZE * BLOCK_COUNT;

/**
 *  定义load函数，加载时运行
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load) {
    switch_api_interface_t *api_interface = nullptr;
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed load starting\n");

    switch_mutex_init(&shm_mutex, SWITCH_MUTEX_NESTED, pool);

    // 保存当前进程的 umask
    mode_t old_mask = umask(0); // 临时取消所有权限屏蔽
    // 创建共享内存
    shm_fd = shm_open("/media_shm", O_CREAT | O_RDWR, 0666);
    umask(old_mask); // 恢复原 umask，避免影响其他文件操作
    if (shm_fd == -1) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "init share memory failed!\n");
    } else {
        ftruncate(shm_fd, BUFFER_SIZE); // BUFFER_SIZE 为共享内存大小
        shm_ptr = (uint8_t*)mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

        memset(shm_ptr, 0, BUFFER_SIZE);

        // register global state handlers
        // switch_core_add_state_handler(&shmed_cs_handlers);
        if (switch_event_bind(modname, SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA, SWITCH_EVENT_SUBCLASS_ANY,
                              on_channel_progress_media, nullptr) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Bind SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA event failed!\n");
        }
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed loaded\n");

    return SWITCH_STATUS_SUCCESS;
}

/**
 *  定义shutdown函数，关闭时运行
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_shmed_shutdown) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed shutdown called\n");

    // unregister global state handlers
    // switch_core_remove_state_handler(&shmed_cs_handlers);

    // 清理
    if (shm_fd != -1) {
        munmap(shm_ptr, BUFFER_SIZE);
        shm_unlink("/media_shm");
    }

    switch_mutex_destroy(shm_mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed unload\n");
    return SWITCH_STATUS_SUCCESS;
}