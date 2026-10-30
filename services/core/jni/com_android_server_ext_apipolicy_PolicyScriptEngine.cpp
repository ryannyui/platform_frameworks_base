/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "ApiPolicyJni"

#include <jni.h>
#include <nativehelper/JNIHelp.h>
#include <utils/Log.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}

namespace android {

namespace {

constexpr int kMaxTableDepth = 4;
constexpr size_t kMaxTableEntries = 128;
constexpr size_t kMaxLogsPerCall = 32;
constexpr size_t kMaxLogLineBytes = 512;
constexpr size_t kTracebackSafetyHeadroomBytes = 32 * 1024;

struct CachedJavaRefs {
    jclass objectClass = nullptr;
    jclass objectArrayClass = nullptr;
    jclass stringClass = nullptr;
    jclass booleanClass = nullptr;
    jclass longClass = nullptr;
    jclass integerClass = nullptr;
    jclass doubleClass = nullptr;
    jclass floatClass = nullptr;
    jclass listClass = nullptr;

    jmethodID booleanValue = nullptr;
    jmethodID booleanValueOf = nullptr;
    jmethodID longValue = nullptr;
    jmethodID longValueOf = nullptr;
    jmethodID intValue = nullptr;
    jmethodID doubleValue = nullptr;
    jmethodID doubleValueOf = nullptr;
    jmethodID floatValue = nullptr;
    jmethodID listAdd = nullptr;
};

CachedJavaRefs gRefs;

struct KvValue;
using KvEntry = std::pair<std::string, KvValue>;
using KvPairs = std::vector<KvEntry>;

struct KvValue {
    enum class Kind { Bool, Int, Num, Str, Table };
    Kind kind = Kind::Bool;
    bool boolVal = false;
    lua_Integer intVal = 0;
    lua_Number numVal = 0.0;
    std::string strVal;
    KvPairs tableVal;
};

struct ScriptVm {
    lua_State* L = nullptr;
    size_t usedBytes = 0;
    size_t maxBytes = 2 * 1024 * 1024;
    bool inInitPhase = false;
    bool timedOut = false;
    std::unordered_map<std::string, int> handlerRefs;
    std::vector<std::string> registeredOrder;
    std::vector<std::string> pendingLogs;
};

struct CompileProtectedCtx {
    const char* srcData;
    size_t srcLen;
    const char* chunkName;
    int maxInitSteps;
};

struct InvokeProtectedCtx {
    int handlerRef;
    const KvPairs* input;
    int maxEvalSteps;
    KvPairs* output;
    bool hasTableResult;
};

inline ScriptVm* getVmFromState(lua_State* L) {
    return *static_cast<ScriptVm**>(lua_getextraspace(L));
}

bool clearIfException(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    return false;
}

// Converts arbitrary 8-bit / UTF-8 byte sequences (including 4-byte UTF-8 emojis, embedded NULs,
// or malformed Lua bytes) into UTF-16 so JNI never triggers CheckJNI Modified-UTF-8 aborts.
jstring utf8ToJavaString(JNIEnv* env, const char* data, size_t len) {
    if (data == nullptr || len == 0) {
        const jchar empty = 0;
        jstring s = env->NewString(&empty, 0);
        if (clearIfException(env)) {
            return nullptr;
        }
        return s;
    }

    std::vector<jchar> utf16;
    utf16.reserve(len);

    size_t i = 0;
    while (i < len) {
        const uint8_t b0 = static_cast<uint8_t>(data[i]);
        if (b0 < 0x80) {
            utf16.push_back(static_cast<jchar>(b0));
            i += 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF && i + 1 < len) {
            const uint8_t b1 = static_cast<uint8_t>(data[i + 1]);
            if ((b1 & 0xC0) == 0x80) {
                const uint32_t cp = ((static_cast<uint32_t>(b0 & 0x1F) << 6) |
                                     static_cast<uint32_t>(b1 & 0x3F));
                utf16.push_back(static_cast<jchar>(cp));
                i += 2;
            } else {
                utf16.push_back(0xFFFD);
                i += 1;
            }
        } else if (b0 >= 0xE0 && b0 <= 0xEF && i + 2 < len) {
            const uint8_t b1 = static_cast<uint8_t>(data[i + 1]);
            const uint8_t b2 = static_cast<uint8_t>(data[i + 2]);
            const bool validCont = ((b1 & 0xC0) == 0x80) && ((b2 & 0xC0) == 0x80);
            const bool overlong = (b0 == 0xE0 && b1 < 0xA0);
            const bool surrogate = (b0 == 0xED && b1 >= 0xA0);
            if (validCont && !overlong && !surrogate) {
                const uint32_t cp = ((static_cast<uint32_t>(b0 & 0x0F) << 12) |
                                     (static_cast<uint32_t>(b1 & 0x3F) << 6) |
                                     static_cast<uint32_t>(b2 & 0x3F));
                utf16.push_back(static_cast<jchar>(cp));
                i += 3;
            } else {
                utf16.push_back(0xFFFD);
                i += 1;
            }
        } else if (b0 >= 0xF0 && b0 <= 0xF4 && i + 3 < len) {
            const uint8_t b1 = static_cast<uint8_t>(data[i + 1]);
            const uint8_t b2 = static_cast<uint8_t>(data[i + 2]);
            const uint8_t b3 = static_cast<uint8_t>(data[i + 3]);
            const bool validCont = ((b1 & 0xC0) == 0x80) && ((b2 & 0xC0) == 0x80) &&
                                   ((b3 & 0xC0) == 0x80);
            const bool overlong = (b0 == 0xF0 && b1 < 0x90);
            const bool outOfRange = (b0 == 0xF4 && b1 > 0x8F);
            if (validCont && !overlong && !outOfRange) {
                uint32_t cp = ((static_cast<uint32_t>(b0 & 0x07) << 18) |
                               (static_cast<uint32_t>(b1 & 0x3F) << 12) |
                               (static_cast<uint32_t>(b2 & 0x3F) << 6) |
                               static_cast<uint32_t>(b3 & 0x3F));
                cp -= 0x10000;
                utf16.push_back(static_cast<jchar>(0xD800 | (cp >> 10)));
                utf16.push_back(static_cast<jchar>(0xDC00 | (cp & 0x3FF)));
                i += 4;
            } else {
                utf16.push_back(0xFFFD);
                i += 1;
            }
        } else {
            utf16.push_back(0xFFFD);
            i += 1;
        }
    }

    jstring res = env->NewString(utf16.data(), static_cast<jsize>(utf16.size()));
    if (clearIfException(env)) {
        return nullptr;
    }
    return res;
}

jstring utf8ToJavaString(JNIEnv* env, const std::string& str) {
    return utf8ToJavaString(env, str.data(), str.size());
}

// Converts a Java UTF-16 String into standard RFC 3629 UTF-8 without pinning GC memory.
bool javaStringToUtf8(JNIEnv* env, jstring jstr, std::string* out) {
    if (jstr == nullptr || out == nullptr) {
        return false;
    }
    const jsize u16Len = env->GetStringLength(jstr);
    if (clearIfException(env)) {
        return false;
    }
    if (u16Len <= 0) {
        out->clear();
        return true;
    }

    std::vector<jchar> u16(static_cast<size_t>(u16Len));
    env->GetStringRegion(jstr, 0, u16Len, u16.data());
    if (clearIfException(env)) {
        return false;
    }

    out->clear();
    out->reserve(static_cast<size_t>(u16Len));

    size_t i = 0;
    const size_t n = u16.size();
    while (i < n) {
        const uint32_t c = u16[i];
        if (c < 0x80) {
            out->push_back(static_cast<char>(c));
            i += 1;
        } else if (c < 0x800) {
            out->push_back(static_cast<char>(0xC0 | (c >> 6)));
            out->push_back(static_cast<char>(0x80 | (c & 0x3F)));
            i += 1;
        } else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n &&
                   u16[i + 1] >= 0xDC00 && u16[i + 1] <= 0xDFFF) {
            const uint32_t low = u16[i + 1];
            const uint32_t cp = 0x10000 + (((c - 0xD800) << 10) | (low - 0xDC00));
            out->push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            i += 2;
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            // Unpaired surrogate -> U+FFFD
            out->append("\xEF\xBF\xBD", 3);
            i += 1;
        } else {
            out->push_back(static_cast<char>(0xE0 | (c >> 12)));
            out->push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | (c & 0x3F)));
            i += 1;
        }
    }
    return true;
}

void* restrictedLuaAlloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    auto* vm = static_cast<ScriptVm*>(ud);
    const size_t actualOldSize = (ptr == nullptr) ? 0 : osize;

    if (nsize == 0) {
        if (ptr != nullptr) {
            if (vm->usedBytes >= actualOldSize) {
                vm->usedBytes -= actualOldSize;
            } else {
                vm->usedBytes = 0;
            }
            std::free(ptr);
        }
        return nullptr;
    }

    if (nsize > actualOldSize) {
        const size_t delta = nsize - actualOldSize;
        if (vm->usedBytes + delta > vm->maxBytes) {
            return nullptr;
        }
    }

    void* newPtr = std::realloc(ptr, nsize);
    if (newPtr == nullptr) {
        return nullptr;
    }

    if (nsize >= actualOldSize) {
        vm->usedBytes += (nsize - actualOldSize);
    } else if (vm->usedBytes >= (actualOldSize - nsize)) {
        vm->usedBytes -= (actualOldSize - nsize);
    } else {
        vm->usedBytes = 0;
    }
    return newPtr;
}

void instructionQuotaHook(lua_State* L, lua_Debug* /*ar*/) {
    ScriptVm* vm = getVmFromState(L);
    if (vm != nullptr && !vm->timedOut) {
        vm->timedOut = true;
        // Re-arm every single instruction so pcall() inside Lua cannot swallow timeouts.
        lua_sethook(L, instructionQuotaHook, LUA_MASKCOUNT, 1);
    }
    luaL_error(L, "execution instruction limit exceeded");
}

int tracebackErrorHandler(lua_State* L) {
    ScriptVm* vm = getVmFromState(L);
    if (vm == nullptr || vm->timedOut ||
        vm->usedBytes + kTracebackSafetyHeadroomBytes > vm->maxBytes) {
        // Avoid allocating a traceback buffer when timed out or near memory exhaustion.
        return 1;
    }
    const char* msg = lua_tostring(L, 1);
    if (msg != nullptr) {
        luaL_traceback(L, L, msg, 1);
    } else {
        lua_pushliteral(L, "(non-string error object)");
    }
    return 1;
}

// Note: No non-trivial C++ stack objects may live across Lua C API calls that can longjmp.
int luaPolicyLogCommon(lua_State* L) {
    ScriptVm* vm = getVmFromState(L);
    if (vm == nullptr || vm->pendingLogs.size() >= kMaxLogsPerCall) {
        return 0;
    }

    char buf[kMaxLogLineBytes + 4];
    size_t pos = 0;
    bool truncated = false;

    const int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        if (i > 1) {
            if (pos < kMaxLogLineBytes) {
                buf[pos++] = ' ';
            } else {
                truncated = true;
                break;
            }
        }
        size_t len = 0;
        const char* str = luaL_tolstring(L, i, &len);
        if (str != nullptr && len > 0) {
            const size_t avail = kMaxLogLineBytes - pos;
            const size_t toCopy = std::min(len, avail);
            if (toCopy > 0) {
                std::memcpy(buf + pos, str, toCopy);
                pos += toCopy;
            }
            if (len > avail) {
                truncated = true;
            }
        }
        lua_pop(L, 1);
        if (truncated) {
            break;
        }
    }

    if (truncated) {
        std::memcpy(buf + pos, "...", 3);
        pos += 3;
    }
    vm->pendingLogs.emplace_back(buf, pos);
    return 0;
}

// Note: Perform all throwing Lua C API calls (including luaL_ref) before constructing C++ strings.
int luaPolicyOn(lua_State* L) {
    ScriptVm* vm = getVmFromState(L);
    if (vm == nullptr || !vm->inInitPhase) {
        return luaL_error(L, "policy.on() may only be called during script initialization");
    }

    size_t idLen = 0;
    const char* pointIdPtr = luaL_checklstring(L, 1, &idLen);
    if (idLen == 0) {
        return luaL_argerror(L, 1, "point_id must not be empty");
    }
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua_pushvalue(L, 2);
    const int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // No throwing Lua calls follow from here onward; C++ allocations are now longjmp-safe.
    std::string pointId(pointIdPtr, idLen);
    auto it = vm->handlerRefs.find(pointId);
    if (it != vm->handlerRefs.end()) {
        luaL_unref(L, LUA_REGISTRYINDEX, it->second);
        it->second = ref;
    } else {
        vm->handlerRefs.emplace(pointId, ref);
        vm->registeredOrder.push_back(std::move(pointId));
    }
    return 0;
}

int luaPolicyNowMs(lua_State* L) {
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
    lua_pushinteger(L, static_cast<lua_Integer>(ms));
    return 1;
}

int luaPolicyElapsedNs(lua_State* L) {
    struct timespec ts {};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) {
        const int64_t ns = static_cast<int64_t>(ts.tv_sec) * 1000000000LL
                + static_cast<int64_t>(ts.tv_nsec);
        lua_pushinteger(L, static_cast<lua_Integer>(ns));
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

void openSandboxedLibs(lua_State* L) {
    luaL_requiref(L, LUA_GNAME, luaopen_base, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);
    lua_pop(L, 1);

    // Pre-intern critical fallback error short strings in LUA_REGISTRYINDEX so Lua never needs to
    // allocate them when reporting LUA_ERRERR or instruction quota timeouts under memory pressure.
    lua_pushliteral(L, "error in error handling");
    luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushliteral(L, "execution instruction limit exceeded");
    luaL_ref(L, LUA_REGISTRYINDEX);

    // Strip unsafe file/bytecode/GC functions from global environment.
    const char* kBlockedGlobals[] = {"dofile", "loadfile", "load", "collectgarbage"};
    for (const char* name : kBlockedGlobals) {
        lua_pushnil(L);
        lua_setglobal(L, name);
    }

    // Redirect print(...) to policy.log(...).
    lua_pushcfunction(L, luaPolicyLogCommon);
    lua_setglobal(L, "print");

    // Register global `policy` helper module.
    static const luaL_Reg kPolicyFuncs[] = {
            {"on", luaPolicyOn},
            {"log", luaPolicyLogCommon},
            {"now_ms", luaPolicyNowMs},
            {"elapsed_ns", luaPolicyElapsedNs},
            {nullptr, nullptr},
    };
    luaL_newlib(L, kPolicyFuncs);
    lua_setglobal(L, "policy");
}

void setStringArrayElement(JNIEnv* env, jobjectArray arr, jsize index, const std::string& value) {
    if (arr == nullptr) {
        return;
    }
    jstring jval = utf8ToJavaString(env, value);
    if (jval != nullptr) {
        env->SetObjectArrayElement(arr, index, jval);
        clearIfException(env);
        env->DeleteLocalRef(jval);
    }
}

void setStringArrayElement(JNIEnv* env, jobjectArray arr, jsize index, const char* value,
                           size_t len) {
    if (arr == nullptr) {
        return;
    }
    jstring jval = utf8ToJavaString(env, value, len);
    if (jval != nullptr) {
        env->SetObjectArrayElement(arr, index, jval);
        clearIfException(env);
        env->DeleteLocalRef(jval);
    }
}

void flushLogsToJavaList(JNIEnv* env, jobject javaList, std::vector<std::string>* logs) {
    if (logs == nullptr || logs->empty()) {
        return;
    }
    if (javaList != nullptr) {
        for (const std::string& line : *logs) {
            jstring jline = utf8ToJavaString(env, line);
            if (jline == nullptr) {
                break;
            }
            env->CallBooleanMethod(javaList, gRefs.listAdd, jline);
            env->DeleteLocalRef(jline);
            if (clearIfException(env)) {
                break;
            }
        }
    }
    logs->clear();
}

// Pure JNI step: extracts Java Object[] flat KV into C++ structures with zero Lua calls.
bool javaFlatKvToCpp(JNIEnv* env, jobjectArray flatKv, int depth, KvPairs* out) {
    out->clear();
    if (flatKv == nullptr || depth > kMaxTableDepth) {
        return true;
    }

    const jsize len = env->GetArrayLength(flatKv);
    if (clearIfException(env) || len <= 1) {
        return true;
    }
    out->reserve(static_cast<size_t>(len / 2));

    for (jsize i = 0; i + 1 < len; i += 2) {
        jobject keyObj = env->GetObjectArrayElement(flatKv, i);
        if (clearIfException(env)) {
            return false;
        }
        if (keyObj == nullptr || !env->IsInstanceOf(keyObj, gRefs.stringClass)) {
            if (keyObj != nullptr) {
                env->DeleteLocalRef(keyObj);
            }
            continue;
        }

        jobject valObj = env->GetObjectArrayElement(flatKv, i + 1);
        if (clearIfException(env)) {
            env->DeleteLocalRef(keyObj);
            return false;
        }
        if (valObj == nullptr) {
            env->DeleteLocalRef(keyObj);
            continue;
        }

        std::string keyUtf8;
        if (!javaStringToUtf8(env, static_cast<jstring>(keyObj), &keyUtf8)) {
            env->DeleteLocalRef(valObj);
            env->DeleteLocalRef(keyObj);
            return false;
        }

        KvValue kv;
        bool supported = true;
        if (env->IsInstanceOf(valObj, gRefs.stringClass)) {
            kv.kind = KvValue::Kind::Str;
            if (!javaStringToUtf8(env, static_cast<jstring>(valObj), &kv.strVal)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
        } else if (env->IsInstanceOf(valObj, gRefs.longClass)) {
            const jlong v = env->CallLongMethod(valObj, gRefs.longValue);
            if (clearIfException(env)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
            kv.kind = KvValue::Kind::Int;
            kv.intVal = static_cast<lua_Integer>(v);
        } else if (env->IsInstanceOf(valObj, gRefs.integerClass)) {
            const jint v = env->CallIntMethod(valObj, gRefs.intValue);
            if (clearIfException(env)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
            kv.kind = KvValue::Kind::Int;
            kv.intVal = static_cast<lua_Integer>(v);
        } else if (env->IsInstanceOf(valObj, gRefs.doubleClass)) {
            const jdouble v = env->CallDoubleMethod(valObj, gRefs.doubleValue);
            if (clearIfException(env)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
            kv.kind = KvValue::Kind::Num;
            kv.numVal = static_cast<lua_Number>(v);
        } else if (env->IsInstanceOf(valObj, gRefs.floatClass)) {
            const jfloat v = env->CallFloatMethod(valObj, gRefs.floatValue);
            if (clearIfException(env)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
            kv.kind = KvValue::Kind::Num;
            kv.numVal = static_cast<lua_Number>(v);
        } else if (env->IsInstanceOf(valObj, gRefs.booleanClass)) {
            const jboolean v = env->CallBooleanMethod(valObj, gRefs.booleanValue);
            if (clearIfException(env)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
            kv.kind = KvValue::Kind::Bool;
            kv.boolVal = (v == JNI_TRUE);
        } else if (env->IsInstanceOf(valObj, gRefs.objectArrayClass)) {
            kv.kind = KvValue::Kind::Table;
            if (!javaFlatKvToCpp(env, static_cast<jobjectArray>(valObj), depth + 1, &kv.tableVal)) {
                env->DeleteLocalRef(valObj);
                env->DeleteLocalRef(keyObj);
                return false;
            }
        } else {
            supported = false;
        }

        env->DeleteLocalRef(valObj);
        env->DeleteLocalRef(keyObj);

        if (supported) {
            out->emplace_back(std::move(keyUtf8), std::move(kv));
        }
    }
    return true;
}

// Runs strictly inside lua_pcall with POD-only stack frames so LUA_ERRMEM longjmp is 100% safe.
void pushCppKvTableToLua(lua_State* L, const KvPairs& pairs, int depth) {
    if (depth > kMaxTableDepth || !lua_checkstack(L, 6)) {
        lua_newtable(L);
        return;
    }

    const size_t count = pairs.size();
    lua_createtable(L, 0, static_cast<int>(count));
    const KvEntry* data = pairs.data();
    for (size_t i = 0; i < count; ++i) {
        const KvEntry& entry = data[i];
        lua_pushlstring(L, entry.first.data(), entry.first.size());
        const KvValue& v = entry.second;
        switch (v.kind) {
            case KvValue::Kind::Bool:
                lua_pushboolean(L, v.boolVal ? 1 : 0);
                break;
            case KvValue::Kind::Int:
                lua_pushinteger(L, v.intVal);
                break;
            case KvValue::Kind::Num:
                lua_pushnumber(L, v.numVal);
                break;
            case KvValue::Kind::Str:
                lua_pushlstring(L, v.strVal.data(), v.strVal.size());
                break;
            case KvValue::Kind::Table:
                pushCppKvTableToLua(L, v.tableVal, depth + 1);
                break;
        }
        lua_rawset(L, -3);
    }
}

// Runs inside lua_pcall; no non-trivial C++ objects live on stack across lua_next.
void readLuaTableToCppKv(lua_State* L, int tableIndex, int depth, KvPairs* out) {
    out->clear();
    if (depth > kMaxTableDepth || !lua_checkstack(L, 6)) {
        return;
    }

    const int absIdx = lua_absindex(L, tableIndex);
    out->reserve(16);

    lua_pushnil(L);
    while (lua_next(L, absIdx) != 0) {
        if (out->size() >= kMaxTableEntries) {
            lua_pop(L, 2);
            break;
        }

        if (lua_type(L, -2) == LUA_TSTRING) {
            size_t keyLen = 0;
            const char* keyPtr = lua_tolstring(L, -2, &keyLen);
            const int valType = lua_type(L, -1);

            if (keyPtr != nullptr) {
                switch (valType) {
                    case LUA_TBOOLEAN: {
                        const bool b = (lua_toboolean(L, -1) != 0);
                        KvValue kv;
                        kv.kind = KvValue::Kind::Bool;
                        kv.boolVal = b;
                        out->emplace_back(std::string(keyPtr, keyLen), std::move(kv));
                        break;
                    }
                    case LUA_TNUMBER: {
                        KvValue kv;
                        if (lua_isinteger(L, -1)) {
                            kv.kind = KvValue::Kind::Int;
                            kv.intVal = lua_tointeger(L, -1);
                        } else {
                            kv.kind = KvValue::Kind::Num;
                            kv.numVal = lua_tonumber(L, -1);
                        }
                        out->emplace_back(std::string(keyPtr, keyLen), std::move(kv));
                        break;
                    }
                    case LUA_TSTRING: {
                        size_t svLen = 0;
                        const char* svPtr = lua_tolstring(L, -1, &svLen);
                        if (svPtr != nullptr) {
                            KvValue kv;
                            kv.kind = KvValue::Kind::Str;
                            kv.strVal.assign(svPtr, svLen);
                            out->emplace_back(std::string(keyPtr, keyLen), std::move(kv));
                        }
                        break;
                    }
                    case LUA_TTABLE: {
                        if (depth < kMaxTableDepth) {
                            KvEntry& slot = out->emplace_back(
                                    std::string(keyPtr, keyLen), KvValue{});
                            slot.second.kind = KvValue::Kind::Table;
                            readLuaTableToCppKv(L, -1, depth + 1, &slot.second.tableVal);
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }
        lua_pop(L, 1);
    }
}

// Pure JNI step: converts C++ KvPairs into Java Object[] with zero Lua calls.
jobjectArray cppKvToJavaFlatKv(JNIEnv* env, const KvPairs& pairs) {
    const size_t n = pairs.size();
    jobjectArray result = env->NewObjectArray(
            static_cast<jsize>(n * 2), gRefs.objectClass, nullptr);
    if (clearIfException(env) || result == nullptr) {
        return nullptr;
    }

    jsize writeIdx = 0;
    for (size_t i = 0; i < n; ++i) {
        const KvEntry& entry = pairs[i];
        jstring jkey = utf8ToJavaString(env, entry.first);
        if (jkey == nullptr) {
            env->DeleteLocalRef(result);
            return nullptr;
        }

        jobject jval = nullptr;
        const KvValue& v = entry.second;
        switch (v.kind) {
            case KvValue::Kind::Bool:
                jval = env->CallStaticObjectMethod(
                        gRefs.booleanClass, gRefs.booleanValueOf, v.boolVal ? JNI_TRUE : JNI_FALSE);
                break;
            case KvValue::Kind::Int:
                jval = env->CallStaticObjectMethod(
                        gRefs.longClass, gRefs.longValueOf, static_cast<jlong>(v.intVal));
                break;
            case KvValue::Kind::Num:
                jval = env->CallStaticObjectMethod(
                        gRefs.doubleClass, gRefs.doubleValueOf, static_cast<jdouble>(v.numVal));
                break;
            case KvValue::Kind::Str:
                jval = utf8ToJavaString(env, v.strVal);
                break;
            case KvValue::Kind::Table:
                jval = cppKvToJavaFlatKv(env, v.tableVal);
                break;
        }

        if (clearIfException(env) || jval == nullptr) {
            if (jval != nullptr) {
                env->DeleteLocalRef(jval);
            }
            env->DeleteLocalRef(jkey);
            env->DeleteLocalRef(result);
            return nullptr;
        }

        env->SetObjectArrayElement(result, writeIdx, jkey);
        const bool errKey = clearIfException(env);
        env->DeleteLocalRef(jkey);
        if (errKey) {
            env->DeleteLocalRef(jval);
            env->DeleteLocalRef(result);
            return nullptr;
        }

        env->SetObjectArrayElement(result, writeIdx + 1, jval);
        const bool errVal = clearIfException(env);
        env->DeleteLocalRef(jval);
        if (errVal) {
            env->DeleteLocalRef(result);
            return nullptr;
        }
        writeIdx += 2;
    }
    return result;
}

int protectedCompileAndInit(lua_State* L) {
    auto* ctx = static_cast<CompileProtectedCtx*>(lua_touserdata(L, 1));
    openSandboxedLibs(L);

    // "t" strictly permits text chunks only (rejects binary bytecode chunks).
    const int loadStatus = luaL_loadbufferx(L, ctx->srcData, ctx->srcLen, ctx->chunkName, "t");
    if (loadStatus != LUA_OK) {
        return lua_error(L);
    }

    lua_sethook(L, instructionQuotaHook, LUA_MASKCOUNT, ctx->maxInitSteps);
    lua_call(L, 0, 0);
    lua_sethook(L, nullptr, 0, 0);
    return 0;
}

int protectedInvokeHandler(lua_State* L) {
    auto* ctx = static_cast<InvokeProtectedCtx*>(lua_touserdata(L, 1));
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->handlerRef);
    pushCppKvTableToLua(L, *ctx->input, 0);

    lua_sethook(L, instructionQuotaHook, LUA_MASKCOUNT, ctx->maxEvalSteps);
    lua_call(L, 1, 1);
    lua_sethook(L, nullptr, 0, 0);

    if (lua_istable(L, -1)) {
        ctx->hasTableResult = true;
        readLuaTableToCppKv(L, -1, 0, ctx->output);
    }
    return 0;
}

void destroyScriptVm(ScriptVm* vm) {
    if (vm == nullptr) {
        return;
    }
    if (vm->L != nullptr) {
        lua_close(vm->L);
        vm->L = nullptr;
    }
    delete vm;
}

jlong nativeCompileScript(JNIEnv* env, jclass /*clazz*/, jstring jscriptId, jstring jsource,
                          jlong maxMemBytes, jint maxInitSteps, jobject outRegisteredPointsList,
                          jobject outInitLogsList, jobjectArray errorOut) {
    if (jsource == nullptr) {
        setStringArrayElement(env, errorOut, 0, "Script source is null");
        return 0;
    }

    std::string srcUtf8;
    if (!javaStringToUtf8(env, jsource, &srcUtf8)) {
        setStringArrayElement(env, errorOut, 0, "Failed to read script source");
        return 0;
    }

    std::string chunkName = "policy";
    if (jscriptId != nullptr) {
        std::string idUtf8;
        if (javaStringToUtf8(env, jscriptId, &idUtf8) && !idUtf8.empty()) {
            chunkName = "@" + idUtf8;
        }
    }

    auto* vm = new ScriptVm();
    vm->maxBytes = (maxMemBytes > 64 * 1024) ? static_cast<size_t>(maxMemBytes)
                                             : static_cast<size_t>(2 * 1024 * 1024);

    vm->L = lua_newstate(restrictedLuaAlloc, vm);
    if (vm->L == nullptr) {
        delete vm;
        setStringArrayElement(env, errorOut, 0, "Failed to initialize Lua VM");
        return 0;
    }

    lua_State* L = vm->L;
    *static_cast<ScriptVm**>(lua_getextraspace(L)) = vm;

    CompileProtectedCtx compileCtx{
            srcUtf8.data(),
            srcUtf8.size(),
            chunkName.c_str(),
            (maxInitSteps > 0) ? maxInitSteps : 50000,
    };

    vm->inInitPhase = true;
    vm->timedOut = false;

    // Light C functions and lightuserdata consume pre-allocated stack slots with zero Lua heap
    // allocation, so every single allocation in openSandboxedLibs + load + init is protected.
    lua_pushcfunction(L, tracebackErrorHandler);
    const int errFuncIdx = lua_gettop(L);
    lua_pushcfunction(L, protectedCompileAndInit);
    lua_pushlightuserdata(L, &compileCtx);

    const int callStatus = lua_pcall(L, 1, 0, errFuncIdx);

    lua_sethook(L, nullptr, 0, 0);
    vm->inInitPhase = false;

    flushLogsToJavaList(env, outInitLogsList, &vm->pendingLogs);

    if (callStatus != LUA_OK) {
        size_t errLen = 0;
        const char* err = lua_tolstring(L, -1, &errLen);
        if (err != nullptr) {
            setStringArrayElement(env, errorOut, 0, err, errLen);
        } else {
            setStringArrayElement(env, errorOut, 0, "Script initialization failed");
        }
        destroyScriptVm(vm);
        return 0;
    }

    lua_settop(L, 0);

    if (outRegisteredPointsList != nullptr) {
        for (const std::string& pt : vm->registeredOrder) {
            jstring jpt = utf8ToJavaString(env, pt);
            if (jpt == nullptr) {
                destroyScriptVm(vm);
                setStringArrayElement(env, errorOut, 0, "Failed to marshal registered hook points");
                return 0;
            }
            env->CallBooleanMethod(outRegisteredPointsList, gRefs.listAdd, jpt);
            env->DeleteLocalRef(jpt);
            if (clearIfException(env)) {
                destroyScriptVm(vm);
                setStringArrayElement(env, errorOut, 0, "Failed to record registered hook points");
                return 0;
            }
        }
    }

    return reinterpret_cast<jlong>(vm);
}

jobjectArray nativeInvokeHandler(JNIEnv* env, jclass /*clazz*/, jlong handle, jstring jpointId,
                                 jobjectArray inputFlatKv, jint maxEvalSteps, jobject logsOutList,
                                 jobjectArray errorOut) {
    if (handle == 0 || jpointId == nullptr) {
        return nullptr;
    }

    auto* vm = reinterpret_cast<ScriptVm*>(handle);
    lua_State* L = vm->L;
    if (L == nullptr) {
        return nullptr;
    }

    std::string pointId;
    if (!javaStringToUtf8(env, jpointId, &pointId)) {
        return nullptr;
    }

    auto it = vm->handlerRefs.find(pointId);
    if (it == vm->handlerRefs.end()) {
        return nullptr;
    }

    KvPairs cppInput;
    if (!javaFlatKvToCpp(env, inputFlatKv, 0, &cppInput)) {
        setStringArrayElement(env, errorOut, 0, "Failed to marshal hook input context");
        return nullptr;
    }

    KvPairs cppOutput;
    InvokeProtectedCtx invokeCtx{
            it->second,
            &cppInput,
            (maxEvalSteps > 0) ? maxEvalSteps : 20000,
            &cppOutput,
            false,
    };

    const int baseTop = lua_gettop(L);
    if (!lua_checkstack(L, 4)) {
        setStringArrayElement(env, errorOut, 0, "Lua stack exhausted before invoke");
        return nullptr;
    }

    lua_pushcfunction(L, tracebackErrorHandler);
    const int errFuncIdx = lua_gettop(L);
    lua_pushcfunction(L, protectedInvokeHandler);
    lua_pushlightuserdata(L, &invokeCtx);

    vm->pendingLogs.clear();
    vm->timedOut = false;

    const int status = lua_pcall(L, 1, 0, errFuncIdx);

    lua_sethook(L, nullptr, 0, 0);
    flushLogsToJavaList(env, logsOutList, &vm->pendingLogs);

    if (status != LUA_OK) {
        size_t errLen = 0;
        const char* err = lua_tolstring(L, -1, &errLen);
        if (err != nullptr) {
            setStringArrayElement(env, errorOut, 0, err, errLen);
        } else {
            setStringArrayElement(env, errorOut, 0, "Runtime error in Lua");
        }
        lua_settop(L, baseTop);
        return nullptr;
    }

    lua_settop(L, baseTop);

    if (!invokeCtx.hasTableResult) {
        return nullptr;
    }
    return cppKvToJavaFlatKv(env, cppOutput);
}

void nativeDestroyScript(JNIEnv* /*env*/, jclass /*clazz*/, jlong handle) {
    if (handle == 0) {
        return;
    }
    auto* vm = reinterpret_cast<ScriptVm*>(handle);
    destroyScriptVm(vm);
}

jclass findGlobalClass(JNIEnv* env, const char* className) {
    jclass local = env->FindClass(className);
    LOG_ALWAYS_FATAL_IF(local == nullptr, "Unable to find class %s", className);
    jclass global = static_cast<jclass>(env->NewGlobalRef(local));
    env->DeleteLocalRef(local);
    LOG_ALWAYS_FATAL_IF(global == nullptr, "Unable to create global ref for %s", className);
    return global;
}

jmethodID findMethod(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID mid = env->GetMethodID(clazz, name, sig);
    LOG_ALWAYS_FATAL_IF(mid == nullptr, "Unable to find method %s%s", name, sig);
    return mid;
}

jmethodID findStaticMethod(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID mid = env->GetStaticMethodID(clazz, name, sig);
    LOG_ALWAYS_FATAL_IF(mid == nullptr, "Unable to find static method %s%s", name, sig);
    return mid;
}

const JNINativeMethod sMethods[] = {
        {"nativeCompileScript",
         "(Ljava/lang/String;Ljava/lang/String;JILjava/util/List;Ljava/util/List;"
         "[Ljava/lang/String;)J",
         reinterpret_cast<void*>(nativeCompileScript)},
        {"nativeInvokeHandler",
         "(JLjava/lang/String;[Ljava/lang/Object;ILjava/util/List;[Ljava/lang/String;)"
         "[Ljava/lang/Object;",
         reinterpret_cast<void*>(nativeInvokeHandler)},
        {"nativeDestroyScript", "(J)V", reinterpret_cast<void*>(nativeDestroyScript)},
};

}  // namespace

int register_android_server_ext_apipolicy_PolicyScriptEngine(JNIEnv* env) {
    gRefs.objectClass = findGlobalClass(env, "java/lang/Object");
    gRefs.objectArrayClass = findGlobalClass(env, "[Ljava/lang/Object;");
    gRefs.stringClass = findGlobalClass(env, "java/lang/String");
    gRefs.booleanClass = findGlobalClass(env, "java/lang/Boolean");
    gRefs.longClass = findGlobalClass(env, "java/lang/Long");
    gRefs.integerClass = findGlobalClass(env, "java/lang/Integer");
    gRefs.doubleClass = findGlobalClass(env, "java/lang/Double");
    gRefs.floatClass = findGlobalClass(env, "java/lang/Float");
    gRefs.listClass = findGlobalClass(env, "java/util/List");

    gRefs.booleanValue = findMethod(env, gRefs.booleanClass, "booleanValue", "()Z");
    gRefs.booleanValueOf =
            findStaticMethod(env, gRefs.booleanClass, "valueOf", "(Z)Ljava/lang/Boolean;");
    gRefs.longValue = findMethod(env, gRefs.longClass, "longValue", "()J");
    gRefs.longValueOf = findStaticMethod(env, gRefs.longClass, "valueOf", "(J)Ljava/lang/Long;");
    gRefs.intValue = findMethod(env, gRefs.integerClass, "intValue", "()I");
    gRefs.doubleValue = findMethod(env, gRefs.doubleClass, "doubleValue", "()D");
    gRefs.doubleValueOf =
            findStaticMethod(env, gRefs.doubleClass, "valueOf", "(D)Ljava/lang/Double;");
    gRefs.floatValue = findMethod(env, gRefs.floatClass, "floatValue", "()F");
    gRefs.listAdd = findMethod(env, gRefs.listClass, "add", "(Ljava/lang/Object;)Z");

    return jniRegisterNativeMethods(
            env, "com/android/server/ext/apipolicy/PolicyScriptEngine", sMethods, NELEM(sMethods));
}

}  // namespace android
