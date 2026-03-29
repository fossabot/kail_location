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

#define SENSOR_TYPE_ACCELEROMETER 1
#define SENSOR_TYPE_STEP_COUNTER 19
#define SENSOR_TYPE_STEP_DETECTOR 18

typedef int (*PollFunc)(void*, void*, int);

static PollFunc original_poll = nullptr;
static bool hook_installed = false;
static bool route_simulation_active = false;

void setRouteSimulationActive(bool active) {
    route_simulation_active = active;
    ALOGI("Route simulation: %s", active ? "ACTIVE" : "INACTIVE");
    if (!active) {
        gait::SensorSimulator::Get().UpdateParams(120.0f, 0, false);
    }
}

static void process_sensor_events(void* buffer, int count) {
    if (!buffer || count <= 0 || count > 64) return;

    if (!route_simulation_active) return;

    sensors_event_t* events = static_cast<sensors_event_t*>(buffer);

    ALOGD("Processing %d sensor events", count);

    gait::SensorSimulator::Get().ProcessSensorEvents(events, count);

    for (int i = 0; i < count; i++) {
        sensors_event_t& e = events[i];

        if (e.type == SENSOR_TYPE_STEP_COUNTER) {
            ALOGI("     STEP_COUNTER modified: %.0f", e.data[0]);
        } else if (e.type == SENSOR_TYPE_STEP_DETECTOR) {
            ALOGI("     STEP_DETECTOR modified: %.0f", e.data[0]);
        } else if (e.type == SENSOR_TYPE_ACCELEROMETER) {
            ALOGD("     ACCEL: %.2f %.2f %.2f", e.data[0], e.data[1], e.data[2]);
        }
    }
}

extern "C" int hooked_poll(void* thiz, void* buffer, int count) {
    int ret = 0;

    if (original_poll) {
        ret = original_poll(thiz, buffer, count);
    }

    if (!buffer || ret <= 0 || ret > 64) return ret;

    process_sensor_events(buffer, ret);

    return ret;
}

static void install_poll_hook() {
    ALOGI("Installing poll hook (hardcoded offset)...");
    
    // Use /proc/self/maps to find base address
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        ALOGE("Failed to open /proc/self/maps");
        return;
    }
    
    void* base = nullptr;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libsensorservice.so")) {
            uint64_t start;
            sscanf(line, "%lx-", &start);
            base = (void*)start;
            ALOGI("Found libsensorservice.so at base=%p", base);
            break;
        }
    }
    fclose(fp);
    
    if (!base) {
        ALOGE("libsensorservice.so not found in maps");
        return;
    }
    
    // Hardcoded offset from dump: poll = 0x394a4
    // void* pollAddr = (void*)((char*)base + 0x394a4);
    
    // ElfImg approach (commented - symbol lookup not working)
    // ElfImg elf("/system/lib64/libsensorservice.so");
    // if (!elf.isValid()) { ALOGE("Failed to load ELF"); return; }
    // void* pollAddr = elf.getSymbolAddressByPrefix("HidlSensorHalWrapper::poll");
    
    if (false && false) {
        // Placeholder to keep code compile
    }
    
    // Use hardcoded offset directly
    void* pollAddr = (void*)((char*)base + 0x394a4);
    ALOGI("Using poll at %p (offset=0x394a4)", pollAddr);
    
    int ret = DobbyHook(pollAddr, (void*)hooked_poll, (void**)&original_poll);
    
    if (ret == 0) {
        ALOGI("✅ Hook SUCCESS!");
        hook_installed = true;
    } else {
        ALOGE("❌ DobbyHook failed: %d", ret);
    }
}

extern "C" {

JNIEXPORT void JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeSetRouteSimulation(
    JNIEnv* env, 
    jclass clazz, 
    jboolean active,
    jfloat spm,
    jint mode
) {
    bool isActive = (active != JNI_FALSE);
    ALOGI("JNI: Set route simulation: active=%d, spm=%.2f, mode=%d", 
          isActive ? 1 : 0, spm, mode);
    
    if (isActive) {
        setRouteSimulationActive(true);
        gait::SensorSimulator::Get().UpdateParams(spm, mode, true);
    } else {
        setRouteSimulationActive(false);
    }
}

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
    ALOGI("JNI: init hook (ElfImg)");

    gait::SensorSimulator::Get().Init();
    install_poll_hook();
    gait::SensorSimulator::Get().ReloadConfig();
}

}
