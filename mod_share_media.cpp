#include <switch.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

bool g_shm_enable = true;

const int BLOCK_SIZE = 512;
const int BLOCK_COUNT = 1024 * 1024;
int shm_fd;
uint8_t* shm_ptr = nullptr;
switch_mutex_t *shm_mutex = nullptr;
int next_block_idx = 0;

const switch_time_t MIN_UPDATE_INTERVAL = 10 * 1000L; // 10 ms

switch_time_t last_update_block_idx_tm = 0;
switch_atomic_t allocated_block_count = 0;
switch_atomic_t update_idx_times = 0;
switch_time_t last_log_tm = 0;

bool need_update_block_idx(const switch_time_t now_tm) {
    return !last_update_block_idx_tm || (now_tm - last_update_block_idx_tm >= MIN_UPDATE_INTERVAL);
}

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
        auto data_size = (uint16_t)((current[1] << 8) | current[0]);
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
            switch_atomic_inc(&allocated_block_count);
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

static void update_block_idx(int block_idx, const switch_time_t now) {
    int idx_dup[2];
    switch_mutex_lock(shm_mutex);
    if (block_idx == next_block_idx) {
        idx_dup[0] = idx_dup[1] = block_idx;
        memcpy(shm_ptr, &idx_dup, sizeof(idx_dup));
        switch_atomic_inc(&update_idx_times);
        if (last_log_tm > 0 && now - last_log_tm >= 1000L * 1000L ) { // log interval: 1 s
            const auto cnt = (float )switch_atomic_read(&allocated_block_count);
            switch_atomic_set(&allocated_block_count, 0);
            const auto times = (float )switch_atomic_read(&update_idx_times);
            switch_atomic_set(&update_idx_times, 0);
            const float duration_in_ms = ((float)(now - last_log_tm) / 1000.0f);
            last_log_tm = now;
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "shmed_alloc_block_speed: %f count/s, update speed: %f times/s\n",
                              cnt * 1000.0f / duration_in_ms,  times * 1000.0f / duration_in_ms);
        } else if (last_log_tm == 0) {
            last_log_tm = now;
        }
        last_update_block_idx_tm = now;
    }
    switch_mutex_unlock(shm_mutex);
}

typedef struct {
    int32_t  local_idx;
    switch_core_session_t *session;
    switch_media_bug_t *bug;
    switch_audio_resampler_t *re_sampler;
} shmed_bug_t;

static switch_bool_t handle_read_media_bug(switch_media_bug_t *bug, shmed_bug_t *pvt, switch_channel_t *channel) {
    uint8_t data[SWITCH_RECOMMENDED_BUFFER_SIZE];
    uint32_t data_len;
    switch_frame_t frame = {nullptr};
    frame.data = data;
    frame.buflen = sizeof(data);
    if (switch_core_media_bug_read(bug, &frame, SWITCH_FALSE) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: handle_read_media_bug => switch_core_media_bug_read failed, ignore!\n",
                          switch_channel_get_uuid(channel));
        return SWITCH_TRUE;
    } else {
        data_len = frame.datalen;
        if (pvt->re_sampler) {
            //====== resample ==== ///
            switch_resample_process(pvt->re_sampler, (int16_t *) data, (int) data_len / 2 / 1);
            memcpy(data, pvt->re_sampler->to, pvt->re_sampler->to_len * 2 * 1);
            data_len = pvt->re_sampler->to_len * 2 * 1;
        }

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

        switch_time_t now_tm = switch_time_now(); //switch_time_ref(); //switch_micro_time_now();
        auto size = (uint16_t)(4 + sizeof(switch_time_t) /* timestamp: 8 bytes */ + data_len);
        if (size > BLOCK_SIZE - 2) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: handle_read_media_bug => datalen:%d exceed block size, ignore!\n",
                              switch_channel_get_uuid(channel), size);
            return SWITCH_TRUE;
        }

        int block_idx = shmed_alloc_block(size, channel);
        if (block_idx > 0) {
            uint8_t *data_ptr = shm_ptr + block_idx * BLOCK_SIZE + 2; // skip 2 bytes for size
            memcpy(data_ptr + sizeof(int32_t), &now_tm, sizeof(switch_time_t));
            memcpy(data_ptr + sizeof(int32_t) + sizeof(switch_time_t), data, data_len);
            // set local idx for block
            memcpy(data_ptr, &pvt->local_idx, sizeof(int32_t));

            if (need_update_block_idx(now_tm)) {
                // update the newest block id to 0 block: notify local agent
                update_block_idx(block_idx, now_tm);
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: no valid block, drop frame %d bytes\n",
                              switch_channel_get_uuid(channel), data_len);
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

static switch_status_t shmed_cleanup_on_channel_destroy(switch_core_session_t *session);

const static switch_state_handler_table_t session_shmed_handlers = {
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
        nullptr,
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
        shmed_cleanup_on_channel_destroy,
        // int flags;
        0
};

static switch_status_t shmed_cleanup_on_channel_destroy(switch_core_session_t *session) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
                      "shmed_cleanup_on_channel_destroy: try to cleanup shmed_bug on session [%s] destroy\n",
                      switch_core_session_get_uuid(session));
    switch_core_session_write_lock(session);
    switch_channel_t *channel = switch_core_session_get_channel(session);
    auto pvt = (shmed_bug_t *)switch_channel_get_private(channel, "shmed_bug");
    if (!pvt) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "shmed_cleanup_on_channel_destroy: [%s]'s shmed_bug is nullptr\n",
                          switch_core_session_get_uuid(session));
        goto unlock;
    }
    switch_channel_set_private(channel, "shmed_bug", nullptr);
    if (pvt->bug) {
        if (SWITCH_STATUS_SUCCESS != switch_core_media_bug_remove(session, &(pvt->bug)) ) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                              "shmed_cleanup_on_channel_destroy: failed to switch_core_media_bug_remove: %s\n",
                              switch_core_session_get_uuid(session));
        }
    }

    if (pvt->re_sampler) {
        switch_resample_destroy(&(pvt->re_sampler));
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[%s]: shmed_cleanup_on_channel_destroy: switch_resample_destroy\n",
                          switch_core_session_get_uuid(session));
        pvt->re_sampler = nullptr;
    }

unlock:
    switch_core_session_rwunlock(session);
    return SWITCH_STATUS_SUCCESS;
}

#define SAMPLE_RATE 8000

static void shmed_hook_session(switch_core_session_t *session) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *channel = switch_core_session_get_channel(session);

    const char *str_idx = switch_channel_get_variable(channel, "local_idx");
    if (!str_idx) {
        // not found local_idx var for session
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                          "shmed_hook_session: [%s] missing local_idx, ignore\n",
                          switch_core_session_get_uuid(session));
        return;
    }

    auto pvt = (shmed_bug_t *)switch_channel_get_private(channel, "shmed_bug");
    if (pvt != nullptr) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"[%s]: session_has_hook_shared_media_already\n",
                          switch_channel_get_uuid(channel));
        return;
    }

    switch_codec_implementation_t read_impl;
    memset(&read_impl, 0, sizeof(switch_codec_implementation_t));
    if ((status = switch_core_session_get_read_impl(session, &read_impl)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                          "[%s]: shmed_hook_session => switch_core_session_get_read_impl failed, and return value: %d, skip\n",
                          switch_core_session_get_uuid(session), status);
        return;
    }

    switch_audio_resampler_t *re_sampler = nullptr;
    if (read_impl.actual_samples_per_second != SAMPLE_RATE) {
        if (switch_resample_create(&re_sampler,
                                   read_impl.actual_samples_per_second,
                                   SAMPLE_RATE,
                                   16 * (read_impl.microseconds_per_packet / 1000) * 2,
                                   SWITCH_RESAMPLE_QUALITY,
                                   1) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: shmed_hook_session Unable to allocate re_sampler, ignore this session\n",
                              switch_channel_get_uuid(channel));
            return;
        }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
                          "[%s]: create re-sampler bcs of media sampler/s is %d but shmed support: %d, while ms/p: %d\n",
                          switch_channel_get_uuid(channel), read_impl.actual_samples_per_second, SAMPLE_RATE, read_impl.microseconds_per_packet);
    }

    pvt = (shmed_bug_t*)switch_core_session_alloc(session, sizeof(shmed_bug_t));
    pvt->local_idx = (int32_t)strtol(str_idx, nullptr, 10);
    pvt->session = session;
    pvt->re_sampler = re_sampler;
    pvt->bug = nullptr;

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
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s]: shmed_hook_session Unable to switch_core_media_bug_add, and return value: %d, skip\n",
                          switch_channel_get_uuid(channel), status);
        return;
    }

    switch_channel_set_private(channel, "shmed_bug", pvt);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"[%s] session_hook_shared_media_success\n", switch_channel_get_uuid(channel));
}

static void on_event_codec(switch_event_t *event) {
    if (g_shm_enable) {
        switch_event_header_t *hdr;
        const char *uuid;

        hdr = switch_event_get_header_ptr(event, "Unique-ID");
        uuid = hdr->value;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "on_event_codec: uuid: %s", uuid);

        switch_core_session *session  = switch_core_session_force_locate(uuid);
        if (!session) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "on_event_codec: locate session [%s] failed, maybe ended\n",
                              uuid);
        } else {
            shmed_hook_session(session);
            switch_core_session_rwunlock(session);
        }
    }
}

const size_t BUFFER_SIZE = BLOCK_SIZE * BLOCK_COUNT;

// shmed_tmdiff timestampInMs
SWITCH_STANDARD_API(shmed_tmdiff_function) {
    if (zstr(cmd)) {
        stream->write_function(stream, "shmed_tmdiff: parameter missing.\n");
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "shmed_tmdiff: parameter missing.\n");
        return SWITCH_STATUS_SUCCESS;
    }

    switch_event_t *event = nullptr;
    if (switch_event_create(&event, SWITCH_EVENT_CUSTOM) == SWITCH_STATUS_SUCCESS) {
        switch_event_set_subclass_name(event, "tm_diff");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "org_tm", cmd);
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

// shmed_handled start_mss
SWITCH_STANDARD_API(shmed_handled_function) {
    if (zstr(cmd)) {
        stream->write_function(stream, "shmed_handled: parameter missing.\n");
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "shmed_handled: parameter missing.\n");
        return SWITCH_STATUS_SUCCESS;
    }

    const long start_mss = strtol(cmd, nullptr, 10);
    const long now = switch_time_now(); //switch_time_ref(); //switch_micro_time_now();
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "handle block delay %ld mss\n", now - start_mss);
    return SWITCH_STATUS_SUCCESS;
}


SWITCH_STANDARD_API(shmed_test_function) {
    if (zstr(cmd)) {
        stream->write_function(stream, "shmed_test: parameter missing.\n");
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "shmed_test: parameter missing.\n");
        return SWITCH_STATUS_SUCCESS;
    }

    switch_memory_pool_t *pool;
    switch_core_new_memory_pool(&pool);
    char *my_cmd = switch_core_strdup(pool, cmd);

    char *argv[10];
    memset(argv, 0, sizeof(char *) * 10);

    if (switch_split(my_cmd, ' ', argv) < 2) {
        stream->write_function(stream, "shmed_test <timeout> <times>\n");
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "shmed_test <timeout> <times>\n");
        goto end;
    }

    {
        long timeout = strtol(argv[0], nullptr, 10);
        long count = strtol(argv[1], nullptr, 10);
        for (int i = 0; i < count; i++) {
            switch_time_t before = switch_time_now(); //switch_time_ref();
            switch_micro_sleep(timeout);
            switch_time_t after = switch_time_now(); //switch_time_ref();
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "sleep %ld mss\n", after - before);
        }
    }
end:
    switch_core_destroy_memory_pool(&pool);
    return SWITCH_STATUS_SUCCESS;
}

#define SHMED_ENABLE_SYNTAX "<on|off>"

SWITCH_STANDARD_API(mod_shmed_enable) {
    if (zstr(cmd)) {
        stream->write_function(stream, "-USAGE: %s\n", SHMED_ENABLE_SYNTAX);
    } else {
        if (!strcasecmp(cmd, "on")) {
            g_shm_enable = true;
            stream->write_function(stream, "shmed enabled\n");
        } else if (!strcasecmp(cmd, "off")) {
            g_shm_enable = false;
            stream->write_function(stream, "shmed disabled\n");
        } else {
            stream->write_function(stream, "-USAGE: %s\n", SHMED_ENABLE_SYNTAX);
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

/*
void dump_event(switch_event_t *event) {
    char *buf;

    switch_event_serialize(event, &buf, SWITCH_TRUE);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "\nEVENT (text version)\n--------------------------------\n%s", buf);
    switch_safe_free(buf);
}
*/

/**
 *  定义load函数，加载时运行
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_shmed_load) {
    switch_api_interface_t *api_interface = nullptr;
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_shmed load starting\n");

    // register API

    SWITCH_ADD_API(api_interface,
                   "shmed_tmdiff",
                   "shmed_tmdiff_function api",
                   shmed_tmdiff_function,
                   "<cmd><args>");

    SWITCH_ADD_API(api_interface,
                   "shmed_handled",
                   "shmed_handled api",
                   shmed_handled_function,
                   "<cmd><args>");

    SWITCH_ADD_API(api_interface,
                   "shmed_test",
                   "shmed_test api",
                   shmed_test_function,
                   "<cmd><args>");

    SWITCH_ADD_API(api_interface,
                   "shmed",
                   "Set shmed feature enabled | disabled",
                   mod_shmed_enable,
                   SHMED_ENABLE_SYNTAX);

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
        switch_core_add_state_handler(&session_shmed_handlers);

        // TODO: switch_event_unbind_callback
        if (switch_event_bind(modname, SWITCH_EVENT_CODEC, SWITCH_EVENT_SUBCLASS_ANY,
                              on_event_codec, nullptr) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Bind SWITCH_EVENT_CODEC event failed!\n");
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
    switch_core_remove_state_handler(&session_shmed_handlers);

    // 清理
    if (shm_fd != -1) {
        munmap(shm_ptr, BUFFER_SIZE);
        shm_unlink("/media_shm");
    }

    switch_mutex_destroy(shm_mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, " mod_shmed unload\n");
    return SWITCH_STATUS_SUCCESS;
}