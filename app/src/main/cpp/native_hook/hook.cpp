#include <jni.h>

#include <android/log.h>
#include <dlfcn.h>
#include <dobby.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <sys/types.h>

#include "sensor_simulator.h"

#define LOG_TAG "NativeHook"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SENSOR_TYPE_ACCELEROMETER 1
#define SENSOR_TYPE_LINEAR_ACCELERATION 10
#define SENSOR_TYPE_STEP_COUNTER 19
#define SENSOR_TYPE_STEP_DETECTOR 18

#define EVENT_SIZE 0x68

typedef long (*WriteFunc)(void*, long);
typedef void (*ConvertFunc)(void*, void*);

static WriteFunc original_write = nullptr;
static ConvertFunc original_convert = nullptr;
static bool write_hook_installed = false;
static bool convert_hook_installed = false;
static bool route_simulation_active = false;
static uint64_t write_offset = 0;
static uint64_t convert_offset = 0;

#define ALOGI_TO_FILE(...) ALOGI(__VA_ARGS__)
#define ALOGE_TO_FILE(...) ALOGE(__VA_ARGS__)

void setRouteSimulationActive(bool active) {
    route_simulation_active = active;
    ALOGI_TO_FILE("Route simulation: %s", active ? "ACTIVE" : "INACTIVE");
    if (!active) {
        gait::SensorSimulator::Get().UpdateParams(120.0f, 0, false);
    }
}

static void process_sensor_event(void* event) {
    if (!event || !route_simulation_active) return;

    int type = *(int*)((char*)event + 0x08);
    int64_t timestamp = *(int64_t*)((char*)event + 0x10);
    float data0 = *(float*)((char*)event + 0x18);
    float data1 = *(float*)((char*)event + 0x1C);
    float data2 = *(float*)((char*)event + 0x20);

    sensors_event_t se;
    memset(&se, 0, sizeof(se));
    se.type = type;
    se.timestamp = timestamp;
    se.data[0] = data0;
    se.data[1] = data1;
    se.data[2] = data2;

    gait::SensorSimulator::Get().ProcessSensorEvents(&se, 1);

    if (type == SENSOR_TYPE_STEP_COUNTER) {
        ALOGI("STEP_COUNTER: %.0f", data0);
    } else if (type == SENSOR_TYPE_STEP_DETECTOR) {
        ALOGI("STEP_DETECTOR: %.0f", data0);
    } else if (type == SENSOR_TYPE_ACCELEROMETER) {
        ALOGI("ACCEL: %.2f %.2f %.2f", data0, data1, data2);
    } else if (type == SENSOR_TYPE_LINEAR_ACCELERATION) {
        ALOGI("LINEAR_ACCEL: %.2f %.2f %.2f", data0, data1, data2);
    }
}

extern "C" long hooked_write(void* events, long count) {

    // ✅ 基础参数校验
    if (!events) {
        ALOGE("events is null!");
        if (original_write) {
            return original_write(events, count);
        }
        return -1;
    }

    if (count <= 0 || count > 1000) {
        ALOGE("invalid count: %ld", count);
        if (original_write) {
            return original_write(events, count);
        }
        return -1;
    }

    // ✅ 遍历 events（带基础防御）
    char* ptr = (char*)events;

    for (long i = 0; i < count; i++) {

        void* event = ptr + i * EVENT_SIZE;

        // 👉 简单地址合法性判断（防野指针）
        uintptr_t addr = (uintptr_t)event;
        if (addr < 0x10000) {
            ALOGE("invalid event ptr: %p", event);
            continue;
        }

        process_sensor_event(event);
    }

    // ✅ 关键：检查 original_write
    if (!original_write) {
        ALOGE("❌ original_write is null! Hook may have failed.");

        // ⚠️ 这里不要 return 0（会吞数据）
        // 👉 推荐返回 count（假装写成功，避免系统异常）
        return count;
    }

    // ✅ 正常走原函数
    return original_write(events, count);
}


extern "C" void hooked_convert(void* inEvent, void* outEvent) {
    if (original_convert) {
        original_convert(inEvent, outEvent);
    }

    if (outEvent) {
        process_sensor_event(outEvent);
    }
}

static void install_write_hook() {
    ALOGI_TO_FILE("Installing SensorEventQueue::write hook...");
    
    void* base = nullptr;
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        ALOGE_TO_FILE("Failed to open /proc/self/maps");
        return;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libsensor.so")) {
            uint64_t start;
            sscanf(line, "%lx-", &start);
            base = (void*)start;
            ALOGI_TO_FILE("Found libsensor.so at base=%p", base);
            break;
        }
    }
    fclose(fp);
    
    if (!base) {
        ALOGE_TO_FILE("libsensor.so not found in maps");
        return;
    }
    
    if (write_offset == 0) {
        ALOGE_TO_FILE("Write offset not configured!");
        return;
    }
    
    void* writeAddr = (void*)((char*)base + write_offset);
    ALOGI_TO_FILE("Using SensorEventQueue::write at %p (offset=0x%lx)", writeAddr, write_offset);
    
    int ret = DobbyHook(writeAddr, (void*)hooked_write, (void**)&original_write);
    
    if (ret == 0) {
        ALOGI_TO_FILE("✅ Write Hook SUCCESS!");
        write_hook_installed = true;
    } else {
        ALOGE("❌ Write DobbyHook failed: %d", ret);
    }
}

static void install_convert_hook() {
    ALOGI_TO_FILE("Installing convertToSensorEvent hook...");
    
    void* base = nullptr;
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        ALOGE_TO_FILE("Failed to open /proc/self/maps");
        return;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libsensorservice.so")) {
            uint64_t start;
            sscanf(line, "%lx-", &start);
            base = (void*)start;
            ALOGI_TO_FILE("Found libsensorservice.so at base=%p", base);
            break;
        }
    }
    fclose(fp);
    
    if (!base) {
        ALOGE_TO_FILE("libsensorservice.so not found in maps");
        return;
    }
    
    if (convert_offset == 0) {
        ALOGE_TO_FILE("Convert offset not configured!");
        return;
    }
    
    void* convertAddr = (void*)((char*)base + convert_offset);
    ALOGI_TO_FILE("Using convertToSensorEvent at %p (offset=0x%lx)", convertAddr, convert_offset);
    
    int ret = DobbyHook(convertAddr, (void*)hooked_convert, (void**)&original_convert);
    
    if (ret == 0) {
        ALOGI_TO_FILE("✅ Convert Hook SUCCESS!");
        convert_hook_installed = true;
    } else {
        ALOGE("❌ Convert DobbyHook failed: %d", ret);
    }
}

extern "C" {

JNIEXPORT void JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeSetWriteOffset(
    JNIEnv* env, 
    jclass clazz, 
    jlong offset
) {
    write_offset = (uint64_t)offset;
    ALOGI_TO_FILE("JNI: Set write offset: 0x%lx", write_offset);
}

JNIEXPORT void JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeSetConvertOffset(
    JNIEnv* env, 
    jclass clazz, 
    jlong offset
) {
    convert_offset = (uint64_t)offset;
    ALOGI_TO_FILE("JNI: Set convert offset: 0x%lx", convert_offset);
}

JNIEXPORT void JNICALL 
Java_com_kail_location_xposed_FakeLocState_nativeSetRouteSimulation(
    JNIEnv* env, 
    jclass clazz, 
    jboolean active,
    jfloat spm,
    jint mode
) {
    bool isActive = (active != JNI_FALSE);
    ALOGI_TO_FILE("JNI: Set route simulation: active=%d, spm=%.2f, mode=%d", 
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
    ALOGI_TO_FILE("JNI: Set gait params spm=%.2f, mode=%d, enable=%d", spm, mode, enable ? 1 : 0);
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
    ALOGI_TO_FILE("JNI: init hook");

    gait::SensorSimulator::Get().Init();
    
    if (write_offset != 0) {
        install_write_hook();
    }
    
    if (convert_offset != 0) {
        install_convert_hook();
    }
    
    gait::SensorSimulator::Get().ReloadConfig();
}

}
