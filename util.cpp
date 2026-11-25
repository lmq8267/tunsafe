// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <string>

#if defined(OS_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif


#if defined(OS_MACOSX)
#include <mach/mach_time.h>
#endif  // OS_MACOSX

#include <vector>
#include <algorithm>
#include "tunsafe_types.h"
#include "tunsafe_endian.h"

static const char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const uint8 *input, size_t length, char *output, size_t output_size, size_t *out_length) {
  char *result, *r;
  const uint8 *end;

  size_t size = (length + 2) / 3 * 4 + 1;

  if (output != NULL) {
    result = output;
    assert(output_size >= size);
    if (output_size < size) {
      *result = 0;
      return NULL;
    }
  } else {
    result = (char*)malloc(size);
    if (!result)
      return NULL;
  }
  r = result;
  end = input + length - 3;
  // Encode full blocks
  while (input <= end) {
    uint32 a = (input[0] << 16) + (input[1] << 8) + input[2];
    input += 3;

    r[0] = kBase64Alphabet[(a >> 18)/* & 0x3F*/];
    r[1] = kBase64Alphabet[(a >> 12) & 0x3F];
    r[2] = kBase64Alphabet[(a >> 6) & 0x3F];
    r[3] = kBase64Alphabet[(a) & 0x3F];
    r += 4;
  }
  if (input == end + 2) {
    uint32 a = input[0] << 4;
    r[0] = kBase64Alphabet[(a >> 6) /*& 0x3F*/];
    r[1] = kBase64Alphabet[(a) & 0x3F];
    r[2] = '=';
    r[3] = '=';
    r += 4;
  } else if (input == end + 1) {
    uint32 a = (input[0] << 10) + (input[1] << 2);
    r[0] = kBase64Alphabet[(a >> 12) /*& 0x3F*/];
    r[1] = kBase64Alphabet[(a >> 6) & 0x3F];
    r[2] = kBase64Alphabet[(a) & 0x3F];
    r[3] = '=';
    r += 4;
  }
  if (out_length)
    *out_length = r - result;
  *r = 0;
  return result;
}

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
  66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
  54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
  10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
  29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66
};

bool base64_decode(const uint8 *in, size_t inLen, uint8 *out, size_t *outLen) {
  const uint8 *end = in + inLen;
  uint8 iter = 0;
  uint32_t buf = 0;
  size_t len = 0;

  while (in < end) {
    unsigned char c = d[*in++];

    switch (c) {
    case WHITESPACE: continue;   /* skip whitespace */
    case INVALID:    return false;   /* invalid input, return error */
    case EQUALS:                 /* pad character, end of data */
      in = end;
      continue;
    default:
      buf = buf << 6 | c;
      iter++;
      if (iter == 4) {
        if ((len += 3) > *outLen) return 0; /* buffer overflow */
        *(out++) = (buf >> 16) & 255;
        *(out++) = (buf >> 8) & 255;
        *(out++) = buf & 255;
        buf = 0; iter = 0;

      }
    }
  }
  if (iter == 3) {
    if ((len += 2) > *outLen) return 0; /* buffer overflow */
    *(out++) = (buf >> 10) & 255;
    *(out++) = (buf >> 2) & 255;
  } else if (iter == 2) {
    if (++len > *outLen) return 0; /* buffer overflow */
    *(out++) = (buf >> 4) & 255;
  }
  *outLen = len;
  return true;
}



std::string FormatCommandOutputForLog(const std::string &text) {
  std::string result;
  bool last_space = false;
  const size_t kMaxLen = 512;
  for (size_t i = 0; i < text.size() && result.size() < kMaxLen; i++) {
    unsigned char c = (unsigned char)text[i];
    if (c == '\r' || c == '\n') {
      if (!result.empty() && !last_space) {
        result += " | ";
        last_space = true;
      }
      continue;
    }
    if (c == '\t')
      c = ' ';
    if (c < 0x20 || c == 0x7f)
      continue;
    if (c == ' ' && (last_space || result.empty()))
      continue;
    result += (char)c;
    last_space = (c == ' ');
  }
  while (!result.empty() && (result.back() == ' ' || result.back() == '|'))
    result.pop_back();
  if (result.size() >= kMaxLen)
    result += "...";
  return result;
}

int RunCommand(const char *fmt, ...) {
  va_list va;
  std::string tmp;
  char buf[32], c;
  char *args[33];
  int nargs = 0;
  bool didadd = false;
  va_start(va, fmt);
  for (;;) {
    c = *fmt++;
    if (c == '%') {
      c = *fmt++;
      if (c == 0) goto ZERO;
      if (c == 's') {
        char *arg = va_arg(va, char*);
        if (arg != NULL) {
          tmp += arg;
          didadd = true;
        }
      } else if (c == 'd') {
        snprintf(buf, 32, "%d", va_arg(va, int));
        tmp += buf;
      } else if (c == '%') {
        tmp += '%';
      }
    } else if (c == ' ' || c == 0) {
ZERO:
      if (!tmp.empty() || didadd) {
        args[nargs++] = _strdup(tmp.c_str());
        tmp.clear();
        if (nargs == 32 || c == 0) break;
      }
      didadd = false;
    } else {
      tmp += c;
    }
  }
  args[nargs] = 0;

  std::string cmdline;
  for (int i = 0; i < nargs; i++) {
    if (i)
      cmdline += ' ';
    cmdline += args[i];
  }
  std::string display_cmd = FormatCommandOutputForLog(cmdline);

  auto free_args = [&]() {
    for (int i = 0; i < nargs; i++)
      free(args[i]);
  };

  if (nargs == 0 || args[0] == NULL || args[0][0] == 0) {
    RERROR("执行失败: 命令为空");
    free_args();
    return -1;
  }

  int ret = -1;
  std::string command_output;
  int exit_code = -1;

#if defined(OS_POSIX)
  int pipefd[2] = {-1, -1};
  if (pipe(pipefd) != 0) {
    RERROR("执行失败: %s；原因: 创建管道失败: %s", display_cmd.c_str(), strerror(errno));
    free_args();
    return -1;
  } else {
    pid_t pid = fork();
    if (pid == 0) {
      close(pipefd[0]);
      dup2(pipefd[1], STDOUT_FILENO);
      dup2(pipefd[1], STDERR_FILENO);
      close(pipefd[1]);
      execvp(args[0], args);
      fprintf(stderr, "execvp %s 失败: %s\n", args[0], strerror(errno));
      _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    if (pid < 0) {
      RERROR("执行失败: %s；原因: fork 失败: %s", display_cmd.c_str(), strerror(errno));
      close(pipefd[0]);
      free_args();
      return -1;
    } else {
      char outbuf[256];
      for (;;) {
        ssize_t n = read(pipefd[0], outbuf, sizeof(outbuf));
        if (n > 0) {
          if (command_output.size() < 2048) {
            size_t room = 2048 - command_output.size();
            if (room > (size_t)n)
              room = (size_t)n;
            command_output.append(outbuf, room);
          }
          continue;
        }
        if (n < 0 && errno == EINTR)
          continue;
        break;
      }
      close(pipefd[0]);
      pipefd[0] = -1;
      if (waitpid(pid, &ret, 0) != pid)
        ret = -1;
    }
  }
#else
  RERROR("执行失败: %s；原因: 当前平台不支持执行命令", display_cmd.c_str());
  free_args();
  return -1;
#endif

  if (ret == 0) {
    exit_code = 0;
  }
#if defined(OS_POSIX)
  else if (ret > 0) {
    if (WIFEXITED(ret))
      exit_code = WEXITSTATUS(ret);
    else if (WIFSIGNALED(ret))
      exit_code = 128 + WTERMSIG(ret);
    else
      exit_code = ret;
  }
#endif

  std::string output = FormatCommandOutputForLog(command_output);
  if (ret == 0) {
    if (output.empty())
      RINFO("执行: %s", display_cmd.c_str());
    else
      RINFO("执行: %s；输出: %s", display_cmd.c_str(), output.c_str());
  } else {
    if (output.empty())
      RERROR("执行失败(%d): %s", exit_code, display_cmd.c_str());
    else
      RERROR("执行失败(%d): %s；输出: %s", exit_code, display_cmd.c_str(), output.c_str());
  }

  for (int i = 0; i < nargs; i++)
    free(args[i]);
  return ret;
}

bool IsOnlyZeros(const uint8 *data, size_t data_size) {
  for (size_t i = 0; i != data_size; i++)
    if (data[i])
      return false;
  return true;
}


#ifdef _MSC_VER
void printhex(const char *name, const void *a, size_t l) {
  char buf[256];
  snprintf(buf, 256, "%s (%d):", name, (int)l); OutputDebugString(buf);
  for (size_t i = 0; i < l; i++) {
    if (i % 4 == 0) printf(" ");
    snprintf(buf, 256, "%.2X", *((uint8*)a + i)); OutputDebugString(buf);
  }
  OutputDebugString("\n");
}

#else
void printhex(const char *name, const void *a, size_t l) {
  printf("%s (%d):", name, (int)l);
  for (size_t i = 0; i < l; i++) {
    if (i % 4 == 0) printf(" ");
    printf("%.2X", *((uint8*)a + i));
  }
  printf("\n");
}
#endif

typedef void Logger(int type, const char *msg);
Logger *g_logger;

//#undef RERROR
#undef void 

extern void (*g_logger)(int level, const char *msg);  
// localtime() 不是线程安全的，而日志会在网络线程等多个线程输出。
// 这里统一用 localtime_r/localtime_s，并集中处理时间、文件名和行号，
// 避免两条日志同时调用 localtime 时出现数据竞争。
static void FormatLogLine(char *final_buf, size_t final_size, const char *file,
                          int line, const char *level, const char *msg) {
  char time_str[64] = "";
  time_t now = time(nullptr);
  struct tm tm_buf;
  struct tm *lt;
#if defined(OS_WIN)
  localtime_s(&tm_buf, &now);
  lt = &tm_buf;
#else
  lt = localtime_r(&now, &tm_buf);
#endif
  if (lt)
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", lt);

  const char *slash1 = strrchr(file, '/');
  const char *slash2 = strrchr(file, '\\');
  const char *filename;
  // 空指针不能参与关系比较，按“优先取路径分隔符中更靠后的一个”处理。
  if (slash1 && (!slash2 || slash1 > slash2))
    filename = slash1 + 1;
  else if (slash2)
    filename = slash2 + 1;
  else
    filename = file;

  snprintf(final_buf, final_size, "%s [%s:%d]%s: %s", time_str, filename, line, level, msg);
}

void RERROR_(const char *file, int line, const char *msg, ...) {
  va_list va;
  char buf[2048];
  char final_buf[3072];

  va_start(va, msg);
  vsnprintf(buf, sizeof(buf), msg, va);
  va_end(va);

  FormatLogLine(final_buf, sizeof(final_buf), file, line, "Error", buf);

  if (g_logger) {
    g_logger(1, final_buf);
  } else {
    fputs(final_buf, stderr);
    fputs("\n", stderr);
  }
}

void RINFO_(const char *file, int line, const char *msg, ...) {
  va_list va;
  char buf[2048];
  char final_buf[3072];

  va_start(va, msg);
  vsnprintf(buf, sizeof(buf), msg, va);
  va_end(va);

  FormatLogLine(final_buf, sizeof(final_buf), file, line, "", buf);

  if (g_logger) {
    g_logger(0, final_buf);
  } else {
    fputs(final_buf, stderr);
    fputs("\n", stderr);
  }
}

void *memdup(const void *p, size_t size) {
  void *x = malloc(size);
  if (x)
    memcpy(x, p, size);
  return x;
}

char *my_strndup(const char *p, size_t size) {
  char *x = (char*)malloc(size + 1);
  if (x) {
    x[size] = 0;
    memcpy(x, p, size);
  }
  return x;
}

size_t my_strlcpy(char *dst, size_t dstsize, const char *src) {
  size_t len = strlen(src);
  if (dstsize) {
    size_t lenx = std::min<size_t>(dstsize - 1, len);
    dst[lenx] = 0;
    memcpy(dst, src, lenx);
  }
  return len;
}

void OsGetRandomBytes(uint8 *data, size_t data_size) {
#if defined(OS_WIN)
  static BOOLEAN(APIENTRY *pfn)(void*, ULONG);
  if (!pfn) {
    pfn = (BOOLEAN(APIENTRY *)(void*, ULONG))GetProcAddress(LoadLibrary("ADVAPI32.DLL"), "SystemFunction036");
    if (!pfn)
      ExitProcess(1);
  }
  if (!pfn(data, (ULONG)data_size)) {
    ExitProcess(1);
    return;
  }
#elif defined(OS_POSIX)
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    RERROR("/dev/urandom 打开失败: %s", strerror(errno));
    exit(1);
  }
  int r = read(fd, data, data_size);
  if (r != data_size) {
    RERROR("/dev/urandom 读取失败: %s", strerror(errno));
    exit(1);
  }
  close(fd);
#else
#error
#endif
}

bool ParseConfigKeyValue(char *m, std::vector<std::pair<char *, char*>> *result) {
  for (;;) {
    char *nl = strchr(m, '\n');
    if (nl)
      *nl = 0;
    if (*m != '\0') {
      char *value = strchr(m, '=');
      if (value == NULL)
        return false;
      *value++ = '\0';
      result->emplace_back(m, value);
    }
    if (!nl)
      return true;
    m = nl + 1;
  }
}

bool ParseHexString(const char *text, void *data, size_t data_size) {
  size_t len = strlen(text);
  if (len != data_size * 2)
    return false;
  for (size_t i = 0; i < data_size; i++) {
    uint32 c = text[i * 2 + 0];
    if (c >= '0' && c <= '9') {
      c -= '0';
    } else if ((c |= 32) >= 'a' && c <= 'f') {
      c -= 'a' - 10;
    } else {
      return false;
    }
    uint32 d = text[i * 2 + 1];
    if (d >= '0' && d <= '9') {
      d -= '0';
    } else if ((d |= 32) >= 'a' && d <= 'f') {
      d -= 'a' - 10;
    } else {
      return false;
    }
    ((uint8*)data)[i] = c * 16 + d;
  }
  return true;
}

bool is_space(uint8_t c) {
  return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}

void SplitString(char *s, int separator, std::vector<char*> *components) {
  components->clear();
  for (;;) {
    while (is_space(*s)) s++;
    char *d = strchr(s, separator);
    if (d == NULL) {
      if (*s)
        components->push_back(s);
      return;
    }
    *d = 0;
    char *e = d;
    while (e > s && is_space(e[-1]))
      *--e = 0;
    components->push_back(s);
    s = d + 1;
  }
}

void PrintHexString(const void *data, size_t data_size, char *result) {
  for (size_t i = 0; i < data_size; i++) {
    uint8 c = ((uint8*)data)[i];
    *result++ = "0123456789abcdef"[c >> 4];
    *result++ = "0123456789abcdef"[c & 0xF];
  }
  *result++ = 0;
}

bool ParseBase64Key(const char *s, uint8 key[32]) {
  size_t size = 32;
  return base64_decode((uint8*)s, strlen(s), key, &size) && size == 32;
}


#if defined(OS_WIN)
uint64 OsGetMilliseconds() {
  return GetTickCount64();
}

void OsGetTimestampTAI64N(uint8 dst[12]) {
  SYSTEMTIME systime;
  uint64 file_time_uint64 = 0;
  GetSystemTime(&systime);
  SystemTimeToFileTime(&systime, (FILETIME*)&file_time_uint64);
  uint64 time_since_epoch_100ns = (file_time_uint64 - 116444736000000000);
  uint64 secs_since_epoch = time_since_epoch_100ns / 10000000 + 0x400000000000000a;
  uint32 nanos = (uint32)(time_since_epoch_100ns % 10000000) * 100;
  WriteBE64(dst, secs_since_epoch);
  WriteBE32(dst + 8, nanos);
}

void OsInterruptibleSleep(int millis) {
  SleepEx(millis, TRUE);
}

#endif  // defined(OS_WIN)


#if defined(OS_POSIX)

#if defined(OS_MACOSX)
static mach_timebase_info_data_t timebase = { 0, 0 };
static uint64_t                  initclock;

void InitOsxGetMilliseconds() {
  if (mach_timebase_info(&timebase) != 0)
    abort();
  initclock = mach_absolute_time();

  timebase.denom *= 1000000;
}

uint64 OsGetMilliseconds() {
  assert(initclock != 0);

  uint64_t clock = mach_absolute_time() - initclock;
  return clock * (uint64_t)timebase.numer / (uint64_t)timebase.denom;
}

#else  // defined(OS_MACOSX)
uint64 OsGetMilliseconds() {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    RERROR("clock_gettime 失败: %s", strerror(errno));
    exit(1);
  }
  return (uint64)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}
#endif

void OsGetTimestampTAI64N(uint8 dst[12]) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  uint64 secs_since_epoch = tv.tv_sec + 0x400000000000000a;
  uint32 nanos = tv.tv_usec * 1000;
  WriteBE64(dst, secs_since_epoch);
  WriteBE32(dst + 8, nanos);
}

void OsInterruptibleSleep(int millis) {
  usleep((useconds_t)millis * 1000);
 }

#endif  // defined(OS_POSIX)
