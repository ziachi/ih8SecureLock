#include <android/log.h>
#include <jni.h>
#include <string.h>

#include "binder.hpp"
#include "zygisk.hpp"

#define LOGD(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, "ih8SecureLock", "[%d] [%s] " fmt, __LINE__, PROC_NAME, ##__VA_ARGS__)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define ARR_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define STR_LEN(a) (ARR_LEN(a) - 1)

#define FLAG_SECURE 0x00002000

#define I_WINDOW_SESSION_DESC u"android.view.IWindowSession"
#define I_ACTIVITY_TASKMANAGER_DESC u"android.app.IActivityTaskManager"

static int sdk = 0;
static uint32_t relayout_code = 0;
static uint32_t relayoutAsync_code = 0;
static uint32_t addToDisplayAsUser_code = 0;
static uint32_t addToDisplay_code = 0;
static uint32_t registerScreenCaptureObserver_code = 0;

static const char* PROC_NAME = "";

static bool getTransactionCodes(JNIEnv* env) {
    relayout_code = getStaticIntFieldJni(env, STUB("android/view/IWindowSession"), TRSCTN("relayout"));
    relayoutAsync_code = getStaticIntFieldJni(env, STUB("android/view/IWindowSession"), TRSCTN("relayoutAsync"));
    addToDisplayAsUser_code = getStaticIntFieldJni(env, STUB("android/view/IWindowSession"), TRSCTN("addToDisplayAsUser"));
    addToDisplay_code = getStaticIntFieldJni(env, STUB("android/view/IWindowSession"), TRSCTN("addToDisplay"));
    registerScreenCaptureObserver_code =
        getStaticIntFieldJni(env, STUB("android/app/IActivityTaskManager"), TRSCTN("registerScreenCaptureObserver"));

    if (registerScreenCaptureObserver_code == 0 && relayoutAsync_code == 0 && relayout_code == 0 &&
        addToDisplayAsUser_code == 0 && addToDisplay_code == 0) {
        LOGD("ERROR getTransactionCodes: Could not get any transaction codes");
        return false;
    }

    if (relayout_code) LOGD("Hook relayout: code=%u", relayout_code);
    if (relayoutAsync_code) LOGD("Hook relayoutAsync: code=%u", relayoutAsync_code);
    if (addToDisplayAsUser_code) LOGD("Hook addToDisplayAsUser: code=%u", addToDisplayAsUser_code);
    if (addToDisplay_code) LOGD("Hook addToDisplay: code=%u", addToDisplay_code);
    if (registerScreenCaptureObserver_code) LOGD("Hook registerScreenCaptureObserver: code=%u", registerScreenCaptureObserver_code);

    return true;
}

// Strip FLAG_SECURE from LayoutParams.flags inside binder parcel.
// LayoutParams layout in parcel: [non-null(4)][length(4)][width(4)][height(4)][x(4)][y(4)][type(4)][flags(4)]...
// relayout params: IWindow, [seq on SDK<=30], LayoutParams attrs, ...
// addToDisplay params: IWindow, seq, LayoutParams attrs, ...   (SDK <= 30, has seq)
// addToDisplayAsUser params: IWindow, LayoutParams attrs, ...  (SDK >= 31, no seq)
static bool stripFlagSecureFromLayoutParams(FakeParcel& parcel, bool has_seq) {
    parcel.skipFlatObj();                              // IWindow flat binder obj
    if (has_seq) parcel.skip(1 * sizeof(uint32_t));    // seq param (present in relayout/addToDisplay on SDK<=30)
    parcel.skip(4 * sizeof(uint32_t));                 // LayoutParams: non-null + length + width + height
    parcel.skip(3 * sizeof(uint32_t));                 // x + y + type

    auto* flags = parcel.peekInt32Ref();
    if (*flags & FLAG_SECURE) {
        *flags &= ~FLAG_SECURE;
        return true;
    }
    return false;
}

int (*transactOrig)(void*, int32_t, uint32_t, void*, void*, uint32_t);

int transactHook(void* self, int32_t handle, uint32_t code, void* pdata, void* preply, uint32_t flags) {
    auto pparcel = (PParcel*)pdata;
    auto parcel = FakeParcel(pparcel->data);

    size_t binder_headers_len = getBinderHeadersLen(sdk);
    if (pparcel->data_size < binder_headers_len + 4) {
        return transactOrig(self, handle, code, pdata, preply, flags);
    }
    parcel.skip(binder_headers_len);

    auto descLen = parcel.readInt32();
    auto desc = parcel.readString16(descLen);

    if (STR_LEN(I_WINDOW_SESSION_DESC) == descLen &&
        memcmp(desc, I_WINDOW_SESSION_DESC, descLen * sizeof(char16_t)) == 0) {

        if (code == relayout_code || code == relayoutAsync_code) {
            // relayout has seq on SDK <= 30
            bool has_seq = (sdk <= 30);
            if (stripFlagSecureFromLayoutParams(parcel, has_seq)) {
                LOGD("Bypassed secure lock (relayout)");
            }
        } else if (code == addToDisplay_code) {
            // addToDisplay (SDK <= 30) always has seq parameter
            if (stripFlagSecureFromLayoutParams(parcel, true)) {
                LOGD("Bypassed secure lock (addToDisplay)");
            }
        } else if (code == addToDisplayAsUser_code) {
            // addToDisplayAsUser (SDK >= 31) has NO seq parameter
            if (stripFlagSecureFromLayoutParams(parcel, false)) {
                LOGD("Bypassed secure lock (addToDisplayAsUser)");
            }
        }
    } else if (code == registerScreenCaptureObserver_code &&
               STR_LEN(I_ACTIVITY_TASKMANAGER_DESC) == descLen &&
               memcmp(desc, I_ACTIVITY_TASKMANAGER_DESC, descLen * sizeof(char16_t)) == 0) {
        LOGD("Bypassed screenshot listener");
        return 0;
    }
    return transactOrig(self, handle, code, pdata, preply, flags);
}

static bool hookBinder(zygisk::Api* api) {
    ino_t inode;
    dev_t dev;
    if (!getMapping("libbinder.so", &inode, &dev)) {
        LOGD("ERROR: Could not get libbinder");
        return false;
    }

    api->pltHookRegister(dev, inode, "_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j",
                         (void**)&transactHook, (void**)&transactOrig);
    if (!api->pltHookCommit()) {
        LOGD("ERROR: pltHookCommit");
        return false;
    }
    return true;
}

static bool run(zygisk::Api* api, JNIEnv* env) {
    sdk = android_get_device_api_level();
    if (sdk <= 0) {
        LOGD("ERROR android_get_device_api_level: %d", sdk);
        return false;
    }
    LOGD("SDK: %d", sdk);
    if (!getTransactionCodes(env)) return false;
    if (!hookBinder(api)) return false;
    return true;
}

class ih8SecureLock : public zygisk::ModuleBase {
   public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        PROC_NAME = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!run(api, env)) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            env->ReleaseStringUTFChars(args->nice_name, PROC_NAME);
        } else {
            LOGD("Loaded");
        }
    }

   private:
    zygisk::Api* api;
    JNIEnv* env;
};

REGISTER_ZYGISK_MODULE(ih8SecureLock)
