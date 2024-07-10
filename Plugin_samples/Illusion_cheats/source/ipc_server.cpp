#include "ipc.hpp"

extern "C"
{
#include "global.h"
#include <sys/mount.h>
    int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
    int32_t sceKernelSuspendProcess(pid_t pid);
    int32_t sceKernelPrepareToResumeProcess(pid_t pid);
    int32_t sceKernelResumeProcess(pid_t pid);
    int32_t sceUserServiceInitialize(int32_t *priority);
    int32_t sceUserServiceGetForegroundUser(int32_t *new_id);
    int32_t scePadSetProcessPrivilege(int32_t num);
}

int launchApp(const char *titleId);

void cheat_log(const char *fmt, ...);

extern "C" int unmount(const char *path, int flags);
bool copyRecursive(const char *source,
                   const char *destination);
bool rmtree(const char *path);
void calculateSize(uint64_t size, char *result);
extern String dump_path;
extern String dump_title;
extern bool is_dumper_enabled;
extern "C" void sceLncUtilGetAppTitleId(uint32_t appId, char *titleId);
bool GetFileContents(const char *path, char **buffer);
uint64_t calculateTotalSize(const char *path);
bool copyFile(const char *source, const char *destination, bool for_dumper);

void notify(bool show_watermark,
            const char *text, ...);
bool isProcessAlive(int pid) noexcept;

static void reply(int appid, bool error,
                  const char *out_var = "Nothing")
{
    char json_str[0x255]; // Adjust the size based on your actual JSON content
    snprintf(json_str, sizeof(json_str), "{\"res\":%d, \"var\":\"%s\"}", error ? -1 : 0, out_var);

    cheat_log("reply: %s\n", json_str);
    int ret = sceAppMessagingSendMsg(appid, TRAINER_RETURN_VALUE, json_str, strlen(json_str), 0);
    if (ret != 0)
    {
        cheat_log("sceAppMessagingSendMsg failed, %x", ret);
        notify(true, "sceAppMessagingSendMsg failed, %x", ret);
    }
}

void *PS_Button_loop(void *);
atomic_bool home_redirect_enabled = false;
atomic_bool home_thread_started = false;
#include <fcntl.h>
// pop -Winfinite-recursion error for this func for clang
#define MB(x) ((size_t)(x) << 20)

#define READ_SIZE 0x1024

bool test_sb_file(const char *filename)
{
    if (!filename)
    {
        cheat_log("test_sb_file: filename is null");
        return false;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        cheat_log("test_sb_file: Failed to open %s", filename);
        return false;
    }

    // Determine the size of the file
    struct stat fileInfo;
    if (fstat(fd, &fileInfo) < 0)
    {
        cheat_log("test_sb_file: Failed to get file size for %s", filename);
        close(fd);
        return false;
    }

    off_t fileSize = fileInfo.st_size;
    char buffer[READ_SIZE];

    // Read start
    if (read(fd, buffer, READ_SIZE) < 0)
    {
        cheat_log("test_sb_file: Failed to read start of %s", filename);
        close(fd);
        return false;
    }

    // Calculate middle, ensuring we don't try to seek beyond the file size
    off_t middlePosition = fileSize / 2 > READ_SIZE ? fileSize / 2 - READ_SIZE / 2 : 0;
    if (lseek(fd, middlePosition, SEEK_SET) < 0 || read(fd, buffer, READ_SIZE) < 0)
    {
        cheat_log("test_sb_file: Failed to read middle of %s", filename);
        close(fd);
        return false;
    }

    // Read end
    off_t endPosition = fileSize > READ_SIZE ? fileSize - READ_SIZE : 0;
    if (lseek(fd, endPosition, SEEK_SET) < 0 || read(fd, buffer, READ_SIZE) < 0)
    {
        cheat_log("test_sb_file: Failed to read end of %s", filename);
        close(fd);
        return false;
    }

    close(fd);
    cheat_log("test_sb_file: Successfully sampled %s", filename);
    return true;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winfinite-recursion"
bool if_exists(const char *path);

int messageThread(void)
{
    static AppMessage msg{};
    int ret = -1;
    int retries = 0;
    json_t const *my_json = nullptr;
    constexpr uint32_t MAX_TOKENS = 256;
    json_t pool[MAX_TOKENS]{};
    String path_buf, path_buf2;
    char size_buf[0x255];
    String json_path;

    while (true)
    {
        if ((ret = sceAppMessagingReceiveMsg(&msg)) < 0)
        {
            cheat_log("sceAppMessagingReceiveMsg failed, %x", ret);
            if (ret == 0x80020003)
            {
                notify(true, "sceAppMessagingReceiveMsg failed, %x, shutting down the server", ret);
                break;
            }
            if (retries > 5)
            {
                notify(true, "sceAppMessagingReceiveMsg failed, %x", ret);
                break;
            }
            retries++;
        }
        int sender_app = msg.sender;
        cheat_log("\nreceived msg from 0x%04x", msg.sender);
        if (msg.msgType == -1)
        {
            cheat_log("msgType: -1");
            break;
        }
        cheat_log("msgType: 0x%x", msg.msgType);
        cheat_log("message size: 0x%x", msg.payloadSize);

        (void)memset(size_buf, 0, sizeof size_buf);

        my_json = json_create((char *)msg.payload, pool, MAX_TOKENS);
        if (!my_json)
        {
            cheat_log("Error parsing JSON");
            notify(true, "Error parsing JSON");
            continue;
        }

        switch (msg.msgType)
        {
        case TRAINER_ACTIVATE_CHEAT:
        {
            GamePatchInfo GameInfo{};
            String proc_name, tid;
            if (!Get_Running_App_TID(tid))
            {
                notify(true, "Failed to get running app");
                reply(sender_app, true);
                break;
            }
            for (auto p : dbg::getProcesses())
            {

                GameInfo.image_pid = p.pid();
                const auto app = getProc(GameInfo.image_pid);
                if (strstr(app->titleId().c_str(), tid.c_str()) != 0)
                {
                    proc_name = p.name();
                    break;
                }
            }
            const UniquePtr<Hijacker> executable = Hijacker::getHijacker(GameInfo.image_pid);
            uintptr_t text_base = 0;
            uint64_t text_size = 0;
            if (!executable)
            {
                cheat_log("Failed to get hijacker");
                reply(sender_app, true);
                break;
            }
            text_base = executable->getEboot()->getTextSection()->start();
            text_size = executable->getEboot()->getTextSection()->sectionLength();
            if (text_base == 0 || text_size == 0)
            {
                cheat_log("text_base == 0 || text_size == 0");
                reply(sender_app, true);
                break;
            }
            GameInfo.image_base = text_base;
            GameInfo.image_size = text_size;
            strcpy(GameInfo.titleID, tid.c_str());
            strcpy(GameInfo.ImageSelf, proc_name.c_str());
            GameInfo.app_mode = (AppType)json_getInteger(json_getProperty(my_json, "app_type"));
            
          //  patch_data1(GameInfo.image_pid, GameInfo.app_mode, , , 0, 0);

            cheat_log("Failed to activate cheats");
            reply(sender_app, true);
            break;
        }
        default:
            notify(false, "Unknown command %s", msg.msgType);
            break;
        }
        msg.msgType = -1;
        msg.sender = -1;
        (void)memset(msg.payload, 0, sizeof(msg.payload));
    }

    return messageThread();
}
#pragma clang diagnostic pop