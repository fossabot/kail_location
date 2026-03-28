#include <jni.h>

#include <android/log.h>
#include <dlfcn.h>
#include <dobby.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <sys/types.h>

#include "sensor_simulator.h"

#define LOG_TAG "NativeHook"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SENSOR_TYPE_STEP_COUNTER 19
#define SENSOR_TYPE_STEP_DETECTOR 18

typedef int (*PollFunc)(void*, sensors_event_t*, int);

static PollFunc original_poll = nullptr;
static bool hook_installed = false;

extern "C" int hooked_poll(void* device, sensors_event_t* buffer, int count);

static void* get_lib_base() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    
    char line[512];
    void* base = nullptr;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libsensorservice.so") && strstr(line, "r-xp")) {
            uint64_t start;
            sscanf(line, "%lx-", &start);
            base = reinterpret_cast<void*>(start);
            ALOGI("libsensorservice.so base: %p", base);
            break;
        }
    }
    
    fclose(fp);
    return base;
}

static void install_poll_hook() {
    void* base = get_lib_base();
    if (!base) {
        ALOGE("Could not find libsensorservice.so base!");
        return;
    }
    
    static constexpr uint32_t kPollOffset = 0x1394a4;
    void* target = reinterpret_cast<char*>(base) + kPollOffset;
    
    ALOGI("Installing poll hook: base=%p target=%p offset=0x%x", base, target, kPollOffset);
    
    int ret = DobbyHook(
        target,
        reinterpret_cast<void*>(&hooked_poll),
        reinterpret_cast<void**>(&original_poll)
    );
    
    if (ret != 0) {
        ALOGE("DobbyHook failed: %d", ret);
        return;
    }
    
    ALOGI("*** Poll hook installed successfully! ***");
    hook_installed = true;
}

static void process_sensor_events(sensors_event_t* events, int count) {
    if (!events || count <= 0) return;
    
    auto& sim = gait::SensorSimulator::Get();
    
    for (int i = 0; i < count; i++) {
        sensors_event_t& evt = events[i];
        
        if (evt.type == SENSOR_TYPE_STEP_COUNTER || evt.type == SENSOR_TYPE_STEP_DETECTOR) {
            sim.ProcessSensorEvent(evt);
        }
    }
}

extern "C" int hooked_poll(void* device, sensors_event_t* buffer, int count) {
    ALOGI(">>> hooked_poll called, count=%d", count);
    
    int result = 0;
    
    if (original_poll) {
        result = original_poll(device, buffer, count);
    }
    
    if (result > 0 && buffer && count > 0) {
        process_sensor_events(buffer, result);
    }
    
    return result;
}

extern "C" {

JNIEXPORT void JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeSetGaitParams(
    JNIEnv* env, 
    jclass clazz, 
    jfloat spm, 
    jint mode, 
    jboolean enable
) {
    ALOGI("JNI: Set gait params spm=%.2f, mode=%d, enable=%d", spm, mode, enable ? 1 : 0);
    gait::SensorSimulator::Get().UpdateParams(spm, mode, enable);
}

JNIEXPORT jboolean JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeReloadConfig(
    JNIEnv* env, 
    jclass clazz
) {
    return gait::SensorSimulator::Get().ReloadConfig() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeInitHook(
    JNIEnv* env, 
    jclass clazz
) {
    ALOGI("JNI: nativeInitHook - installing SensorDevice::poll hook");
    
    gait::SensorSimulator::Get().Init();
    install_poll_hook();
    gait::SensorSimulator::Get().ReloadConfig();
}

}
