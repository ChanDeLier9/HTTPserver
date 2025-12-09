// http_server.c 统一整合版，支持配置文件、静态服务、/search、Basic认证、Session认证、JWT认证
// 依赖：cJSON（需同目录下有cJSON.c/cJSON.h），gcc编译
// 编译示例：gcc http_server.c cJSON.c -o http_server -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include "cJSON.h"
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#define BUF_SIZE 8192
#define MAX_SESSIONS 128
#define SESSION_ID_LEN 32
#define JWT_TOKEN_LEN 256

// 配置结构体
struct Config {
    char address[32];
    int port;
    char system_log[128];
    char access_log[128];
    char log_level[16];
    char username[64];
    char password[64];
    char session_secret[64];
    int session_timeout;
    char jwt_secret[64];
    int jwt_expire;
};

// Session结构体
struct Session {
    char id[SESSION_ID_LEN+1];
    char username[64];
    time_t expire;
};

// Session表
struct Session session_table[MAX_SESSIONS];

// 生成随机SessionID
typedef uint32_t u32;
void gen_session_id(char *sid, int len) {
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < len; ++i) sid[i] = hex[rand()%16];
    sid[len] = 0;
}

// 查找Session
struct Session* find_session(const char *sid) {
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (session_table[i].id[0] && strcmp(session_table[i].id, sid) == 0) {
            if (session_table[i].expire > time(NULL)) return &session_table[i];
        }
    }
    return NULL;
}

// 创建Session
struct Session* create_session(const char *username, int timeout) {
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (session_table[i].id[0] == 0 || session_table[i].expire <= time(NULL)) {
            gen_session_id(session_table[i].id, SESSION_ID_LEN);
            strncpy(session_table[i].username, username, sizeof(session_table[i].username)-1);
            session_table[i].expire = time(NULL) + timeout;
            return &session_table[i];
        }
    }
    return NULL;
}

// 日志等级枚举
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

// 日志等级字符串转枚举
LogLevel get_log_level(const char *level) {
    if (strcasecmp(level, "DEBUG") == 0) return LOG_DEBUG;
    if (strcasecmp(level, "INFO") == 0) return LOG_INFO;
    if (strcasecmp(level, "WARNING") == 0) return LOG_WARNING;
    if (strcasecmp(level, "ERROR") == 0) return LOG_ERROR;
    return LOG_INFO;
}

// 日志记录函数
void write_log(const char* log_file, LogLevel min_level, LogLevel level, const char* format, ...) {
    if (level < min_level) return;
    time_t now;
    struct tm *tm_info;
    char time_str[26];
    char level_str[16];
    va_list args;
    time(&now);
    tm_info = localtime(&now);
    strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    switch(level) {
        case LOG_DEBUG: strcpy(level_str, "DEBUG"); break;
        case LOG_INFO: strcpy(level_str, "INFO"); break;
        case LOG_WARNING: strcpy(level_str, "WARNING"); break;
        case LOG_ERROR: strcpy(level_str, "ERROR"); break;
    }
    FILE *log_fp = fopen(log_file, "a");
    if (log_fp == NULL) return;
    fprintf(log_fp, "[%s] [%s] ", time_str, level_str);
    va_start(args, format);
    vfprintf(log_fp, format, args);
    va_end(args);
    fprintf(log_fp, "\n");
    fclose(log_fp);
}

// ... 这里后续补充全局变量、session表、jwt工具函数等 ...

// Base64解码（仅支持简单用法）
int base64_decode(const char *in, unsigned char *out, int outlen) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = 0, val = 0, valb = -8;
    for (; *in && *in != '=' && len < outlen-1; ++in) {
        const char *p = strchr(tbl, *in);
        if (!p) break;
        val = (val << 6) + (p - tbl);
        valb += 6;
        if (valb >= 0) {
            out[len++] = (val >> valb) & 0xFF;
            valb -= 8;
        }
    }
    out[len] = 0;
    return len;
}

// base64编码
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void base64_encode(const unsigned char *in, int inlen, char *out, int outlen) {
    int i, j;
    for (i = 0, j = 0; i < inlen && j+4 < outlen; i += 3) {
        int v = in[i]<<16 | ((i+1<inlen)?in[i+1]<<8:0) | ((i+2<inlen)?in[i+2]:0);
        out[j++] = b64_table[(v>>18)&0x3F];
        out[j++] = b64_table[(v>>12)&0x3F];
        out[j++] = (i+1<inlen) ? b64_table[(v>>6)&0x3F] : '=';
        out[j++] = (i+2<inlen) ? b64_table[v&0x3F] : '=';
    }
    out[j] = 0;
}
// 生成JWT
void make_jwt(const char *username, const char *secret, int expire, char *out, int outlen) {
    char header[64], payload[256], sig[64], jwt[512];
    snprintf(header, sizeof(header), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    time_t now = time(NULL);
    snprintf(payload, sizeof(payload), "{\"sub\":\"%s\",\"exp\":%ld}", username, now+expire);
    char b64_header[128], b64_payload[256];
    base64_encode((unsigned char*)header, strlen(header), b64_header, sizeof(b64_header));
    base64_encode((unsigned char*)payload, strlen(payload), b64_payload, sizeof(b64_payload));
    snprintf(jwt, sizeof(jwt), "%s.%s", b64_header, b64_payload);
    unsigned int siglen=0;
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)jwt, strlen(jwt), hmac, &siglen);
    char b64_sig[128];
    base64_encode(hmac, siglen, b64_sig, sizeof(b64_sig));
    snprintf(out, outlen, "%s.%s", jwt, b64_sig);
}
// 校验JWT
int verify_jwt(const char *token, const char *secret, char *username, int userlen) {
    char *dot1 = strchr(token, '.');
    if (!dot1) return 0;
    char *dot2 = strchr(dot1+1, '.');
    if (!dot2) return 0;
    int hlen = dot1-token, plen = dot2-dot1-1, slen = strlen(dot2+1);
    char jwt[512];
    snprintf(jwt, sizeof(jwt), "%.*s.%.*s", hlen, token, plen, dot1+1);
    unsigned int siglen=0;
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)jwt, strlen(jwt), hmac, &siglen);
    char b64_sig[128];
    base64_encode(hmac, siglen, b64_sig, sizeof(b64_sig));
    if (strncmp(b64_sig, dot2+1, strlen(b64_sig))) return 0;
    // 解码payload
    char b64_payload[256];
    strncpy(b64_payload, dot1+1, plen); b64_payload[plen]=0;
    unsigned char payload[256];
    base64_decode(b64_payload, payload, sizeof(payload));
    char *sub = strstr((char*)payload, "\"sub\":");
    char *exp = strstr((char*)payload, "\"exp\":");
    if (!sub || !exp) return 0;
    // 修正格式串，正确提取sub
    sscanf(sub, "\\\"sub\\\":\\\"%[^\"]\\\"", username);
    long expv=0; sscanf(exp, "\"exp\":%ld", &expv);
    if (expv < time(NULL)) return 0;
    return 1;
}

// 检查Basic认证
int check_basic_auth(const char *header, const char *username, const char *password) {
    const char *auth = strstr(header, "Authorization: Basic ");
    if (!auth) return 0;
    auth += strlen("Authorization: Basic ");
    char decoded[128] = {0};
    base64_decode(auth, (unsigned char*)decoded, sizeof(decoded));
    char userpass[128];
    snprintf(userpass, sizeof(userpass), "%s:%s", username, password);
    return strcmp(decoded, userpass) == 0;
}

// 读取并解析config.json
int load_config(const char *filename, struct Config *cfg) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    char buf[2048];
    size_t len = fread(buf, 1, sizeof(buf)-1, fp);
    buf[len] = '\0';
    fclose(fp);
    cJSON *root = cJSON_Parse(buf);
    if (!root) return -2;
    cJSON *server = cJSON_GetObjectItem(root, "server");
    strcpy(cfg->address, cJSON_GetObjectItem(server, "address")->valuestring);
    cfg->port = cJSON_GetObjectItem(server, "port")->valueint;
    cJSON *log = cJSON_GetObjectItem(root, "log");
    strcpy(cfg->system_log, cJSON_GetObjectItem(log, "system_log")->valuestring);
    strcpy(cfg->access_log, cJSON_GetObjectItem(log, "access_log")->valuestring);
    strcpy(cfg->log_level, cJSON_GetObjectItem(log, "level")->valuestring);
    cJSON *auth = cJSON_GetObjectItem(root, "auth");
    strcpy(cfg->username, cJSON_GetObjectItem(auth, "username")->valuestring);
    strcpy(cfg->password, cJSON_GetObjectItem(auth, "password")->valuestring);
    cJSON *session = cJSON_GetObjectItem(root, "session");
    strcpy(cfg->session_secret, cJSON_GetObjectItem(session, "secret")->valuestring);
    cfg->session_timeout = cJSON_GetObjectItem(session, "timeout")->valueint;
    cJSON *jwt = cJSON_GetObjectItem(root, "jwt");
    strcpy(cfg->jwt_secret, cJSON_GetObjectItem(jwt, "secret")->valuestring);
    cfg->jwt_expire = cJSON_GetObjectItem(jwt, "expire")->valueint;
    cJSON_Delete(root);
    return 0;
}

// 错误页面处理函数
void send_error_page(int client, int code) {
    const char *title = code == 403 ? "403 Forbidden" : "404 Not Found";
    const char *msg = code == 403 ? "访问被拒绝：不安全的路径" : "请求的文件不存在";
    char html[2048];
    snprintf(html, sizeof(html),
        "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<div style='max-width:900px;margin:30px auto;padding:20px;background:#fafbfc;border-radius:12px;box-shadow:0 2px 8px #eee;text-align:center;'>"
        "<h2 style='color:#e74c3c;margin:30px 0 10px 0;'>%s</h2>"
        "<p style='color:#555;font-size:18px;'>%s</p>"
        "<a href='/' style='color:#2196f3;font-size:16px;text-decoration:none;'>返回首页</a>"
        "</div>",
        code, code == 403 ? "Forbidden" : "Not Found", title, msg);
    ssize_t sent = send(client, html, strlen(html), 0);
    (void)sent; // 忽略返回值，防止未使用警告
}

// 修改send_static_file，找不到文件时调用send_error_page(404)
int send_static_file(int client, const char *filepath, const char *access_log, LogLevel min_level) {
    // 路径安全检查，禁止..
    if (strstr(filepath, "..")) {
        send_error_page(client, 403);
        write_log(access_log, min_level, LOG_WARNING, "不安全的路径访问: %s", filepath);
        return -1;
    }
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        send_error_page(client, 404);
        write_log(access_log, min_level, LOG_WARNING, "静态文件未找到: %s", filepath);
        return -1;
    }
    char buf[BUF_SIZE];
    size_t n;
    // 简单MIME类型判断
    const char *ext = strrchr(filepath, '.');
    const char *mime = "application/octet-stream";
    if (ext) {
        if (strcmp(ext, ".html") == 0) mime = "text/html; charset=utf-8";
        else if (strcmp(ext, ".css") == 0) mime = "text/css; charset=utf-8";
        else if (strcmp(ext, ".js") == 0) mime = "application/javascript; charset=utf-8";
        else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) mime = "image/jpeg";
        else if (strcmp(ext, ".png") == 0) mime = "image/png";
        else if (strcmp(ext, ".gif") == 0) mime = "image/gif";
        else if (strcmp(ext, ".ico") == 0) mime = "image/x-icon";
    }
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n", mime);
    send(client, buf, strlen(buf), 0);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        send(client, buf, n, 0);
    }
    fclose(fp);
    write_log(access_log, min_level, LOG_INFO, "静态文件访问: %s", filepath);
    return 0;
}

// URL解码
void urldecode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10); else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10); else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

// 修改 parse_post_data
void parse_post_data(const char *body, char *class_val, char *keyword_val) {
    char *class_pos = strstr(body, "class=");
    char *keyword_pos = strstr(body, "keyword=");
    if (class_pos) {
        class_pos += 6;
        int len = 0;
        while (class_pos[len] && class_pos[len] != '&') len++;
        strncpy(class_val, class_pos, len);
        class_val[len] = '\0';
        urldecode(class_val, class_val); // URL解码
    }
    if (keyword_pos) {
        keyword_pos += 8;
        int len = 0;
        while (keyword_pos[len] && keyword_pos[len] != '&') len++;
        strncpy(keyword_val, keyword_pos, len);
        keyword_val[len] = '\0';
        urldecode(keyword_val, keyword_val); // URL解码
    }
}

// 查询2011.txt
void search_txt(const char *class_val, const char *keyword_val, char *result, int result_size) {
    FILE *fp = fopen("2011.txt", "r");
    if (!fp) {
        snprintf(result, result_size, "<p>无法打开数据文件！</p>");
        return;
    }
    char line[256];
    int found = 0;
    strcat(result, "<table border=\"1\"><tr><th>学号</th><th>姓名</th><th>性别</th></tr>");
    fgets(line, sizeof(line), fp); // 跳过表头
    while (fgets(line, sizeof(line), fp)) {
        char id[32], name[32], gender[8];
        int ret = sscanf(line, "%s %s %s", id, name, gender);
        if (ret < 3) continue;
        int match_class = 1;
        if (class_val[0]) {
            char class_in_id[8] = {0};
            strncpy(class_in_id, id, 7);
            class_in_id[7] = '\0';
            if (strcmp(class_in_id, class_val) != 0)
                match_class = 0;
        }
        int match_keyword = 1;
        if (keyword_val[0]) {
            if (!strstr(id, keyword_val) && !strstr(name, keyword_val) && !strstr(gender, keyword_val))
                match_keyword = 0;
        }
        if (match_class && match_keyword) {
            char row[128];
            snprintf(row, sizeof(row), "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", id, name, gender);
            strcat(result, row);
            found = 1;
        }
    }
    strcat(result, "</table>");
    if (!found) strcat(result, "<p>未找到匹配结果。</p>");
    fclose(fp);
}

// 处理 /search 路由
int handle_search(int client, const char *method, const char *buf, const char *access_log, LogLevel min_level) {
    if (strcmp(method, "GET") == 0) {
        return send_static_file(client, "search.html", access_log, min_level);
    } else if (strcmp(method, "POST") == 0) {
        // 找到body
        const char *body = strstr(buf, "\r\n\r\n");
        if (!body) return -1;
        body += 4;
        char class_val[32] = {0}, keyword_val[32] = {0};
        parse_post_data(body, class_val, keyword_val);
        char result[BUF_SIZE*2] = {0};
        strcat(result, "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><title>查询结果</title></head><body>");
        strcat(result, "<h2>查询结果：</h2>");
        search_txt(class_val, keyword_val, result+strlen(result), sizeof(result)-strlen(result));
        strcat(result, "<br><a href=\"/search\">返回查询</a></body></html>");
        const char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n";
        send(client, header, strlen(header), 0);
        send(client, result, strlen(result), 0);
        write_log(access_log, min_level, LOG_INFO, "/search 查询: class=%s, keyword=%s", class_val, keyword_val);
        return 0;
    }
    return -1;
}

// 处理 /secured 路由
int handle_secured(int client, const char *buf, const char *username, const char *password, const char *access_log, LogLevel min_level) {
    if (!check_basic_auth(buf, username, password)) {
        const char *resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Secured\"\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            "<html><head><meta http-equiv='refresh' content='5;url=/secured'><title>认证失败</title></head>"
            "<body><h2>认证失败，请重新登录</h2><p>5秒后自动跳转到登录页面...</p></body></html>";
        send(client, resp, strlen(resp), 0);
        write_log(access_log, min_level, LOG_WARNING, "/secured 认证失败");
        write_log("log/system.log", LOG_INFO, LOG_WARNING, "/secured 认证失败");
        return -1;
    }
    const char *resp = "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Type: text/html; charset=utf-8\r\n\r\n登录成功，正在跳转到博客首页...";
    send(client, resp, strlen(resp), 0);
    write_log(access_log, min_level, LOG_INFO, "/secured 认证成功");
    write_log("log/system.log", LOG_INFO, LOG_INFO, "/secured 认证成功");
    return 0;
}

// 处理 /session_login 路由
int handle_session_login(int client, const char *buf, const char *username, const char *password, int timeout, const char *access_log, LogLevel min_level) {
    // 只支持POST，body: username=xxx&password=yyy
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    char u[64]={0}, p[64]={0};
    sscanf(body, "username=%63[^&]&password=%63s", u, p);
    if (strcmp(u, username) == 0 && strcmp(p, password) == 0) {
        struct Session *sess = create_session(username, timeout);
        if (!sess) return -1;
        char header[256];
        snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nSet-Cookie: SESSIONID=%s; Path=/; HttpOnly\r\nContent-Type: text/html; charset=utf-8\r\n\r\n登录成功，SESSIONID=%s", sess->id, sess->id);
        send(client, header, strlen(header), 0);
        write_log(access_log, min_level, LOG_INFO, "/session_login 登录成功");
        return 0;
    }
    const char *resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\n\r\n用户名或密码错误";
    send(client, resp, strlen(resp), 0);
    write_log(access_log, min_level, LOG_WARNING, "/session_login 登录失败");
    return -1;
}

// 处理 /session 路由
int handle_session(int client, const char *buf, const char *access_log, LogLevel min_level) {
    // 查找Cookie
    const char *cookie = strstr(buf, "Cookie: ");
    if (!cookie) goto fail;
    cookie += 8;
    char sid[SESSION_ID_LEN+1] = {0};
    sscanf(cookie, "SESSIONID=%32s", sid);
    struct Session *sess = find_session(sid);
    if (!sess) goto fail;
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\nSession认证成功，欢迎！";
    send(client, resp, strlen(resp), 0);
    write_log(access_log, min_level, LOG_INFO, "/session 认证成功");
    return 0;
fail:
    {
        const char *resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\n\r\nSession认证失败，请先登录";
        send(client, resp, strlen(resp), 0);
        write_log(access_log, min_level, LOG_WARNING, "/session 认证失败");
        return -1;
    }
}

// 处理 /jwt_login 路由
int handle_jwt_login(int client, const char *buf, const char *username, const char *password, const char *jwt_secret, int jwt_expire, const char *access_log, LogLevel min_level) {
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    char u[64]={0}, p[64]={0};
    sscanf(body, "username=%63[^&]&password=%63s", u, p);
    if (strcmp(u, username) == 0 && strcmp(p, password) == 0) {
        char token[JWT_TOKEN_LEN];
        make_jwt(username, jwt_secret, jwt_expire, token, sizeof(token));
        char header[512];
        snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n登录成功，JWT=%s", token);
        send(client, header, strlen(header), 0);
        write_log(access_log, min_level, LOG_INFO, "/jwt_login 登录成功");
        return 0;
    }
    const char *resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\n\r\n用户名或密码错误";
    send(client, resp, strlen(resp), 0);
    write_log(access_log, min_level, LOG_WARNING, "/jwt_login 登录失败");
    return -1;
}
// 处理 /jwt 路由
int handle_jwt(int client, const char *buf, const char *jwt_secret, const char *access_log, LogLevel min_level) {
    // 查找Authorization: Bearer ...
    const char *auth = strstr(buf, "Authorization: Bearer ");
    if (!auth) goto fail;
    auth += strlen("Authorization: Bearer ");
    char username[64]={0};
    if (!verify_jwt(auth, jwt_secret, username, sizeof(username))) goto fail;
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\nJWT认证成功，欢迎！";
    send(client, resp, strlen(resp), 0);
    write_log(access_log, min_level, LOG_INFO, "/jwt 认证成功");
    return 0;
fail:
    {
        const char *resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\n\r\nJWT认证失败，请先登录";
        send(client, resp, strlen(resp), 0);
        write_log(access_log, min_level, LOG_WARNING, "/jwt 认证失败");
        return -1;
    }
}

int main(int argc, char *argv[]) {
    struct Config config;
    if (load_config("config.json", &config) != 0) {
        printf("配置文件加载失败！\n");
        write_log("log/system.log", LOG_INFO, LOG_ERROR, "配置文件加载失败！");
        return 1;
    }
    // 自动创建log目录
    struct stat st = {0};
    if (stat("log", &st) == -1) {
        mkdir("log", 0755);
        write_log("log/system.log", LOG_INFO, LOG_INFO, "自动创建log目录");
    }
    // 强制日志路径加log/前缀
    char access_log_path[256], system_log_path[256];
    snprintf(access_log_path, sizeof(access_log_path), "log/%s", config.access_log);
    snprintf(system_log_path, sizeof(system_log_path), "log/%s", config.system_log);
    strcpy(config.access_log, access_log_path);
    strcpy(config.system_log, system_log_path);
    srand(time(NULL));
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        write_log(config.system_log, LOG_INFO, LOG_ERROR, "socket 创建失败: %s", strerror(errno));
        return 1;
    }
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(config.address);
    serv_addr.sin_port = htons(config.port);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(server_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        write_log(config.system_log, LOG_INFO, LOG_ERROR, "bind 失败: %s", strerror(errno));
        return 1;
    }
    listen(server_sock, 10);
    // main函数启动时只输出两行
    printf("HTTP服务器启动成功，监听 %s:%d\n", config.address, config.port);
    printf("登录地址: http://localhost:%d/secured\n", config.port);
    write_log(config.system_log, LOG_INFO, LOG_INFO, "HTTP服务器启动成功，监听 %s:%d", config.address, config.port);
    LogLevel min_level = get_log_level(config.log_level);
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client = accept(server_sock, (struct sockaddr*)&cli_addr, &cli_len);
        if (client < 0) {
            write_log(config.system_log, min_level, LOG_ERROR, "accept 失败: %s", strerror(errno));
            continue;
        }
        char buf[BUF_SIZE+1];
        int len = recv(client, buf, BUF_SIZE, 0);
        if (len <= 0) {
            write_log(config.system_log, min_level, LOG_WARNING, "客户端连接接收失败或关闭");
            close(client);
            continue;
        }
        buf[len] = 0;
        char method[8], path[128];
        sscanf(buf, "%7s %127s", method, path);
        // 打印到终端：客户端IP、请求方法、请求路径（改为写入system.log）
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
        write_log(config.system_log, min_level, LOG_INFO, "[HTTP] %s %s %s", client_ip, method, path);
        // 路由分发
        int ret = 0;
        int is_root = 0, is_secured = 0, is_secured_unauth = 0;
        if (strcmp(path, "/") == 0) {
            ret = send_static_file(client, "index.html", config.access_log, min_level);
            is_root = 1;
        } else if (strcmp(path, "/search") == 0) {
            ret = handle_search(client, method, buf, config.access_log, min_level);
        } else if (strcmp(path, "/secured") == 0) {
            // 检查是否认证
            if (!check_basic_auth(buf, config.username, config.password)) {
                is_secured = 1;
                is_secured_unauth = 1;
            }
            ret = handle_secured(client, buf, config.username, config.password, config.access_log, min_level);
        } else if (strcmp(path, "/session_login") == 0) {
            ret = handle_session_login(client, buf, config.username, config.password, config.session_timeout, config.access_log, min_level);
        } else if (strcmp(path, "/session") == 0) {
            ret = handle_session(client, buf, config.access_log, min_level);
        } else if (strcmp(path, "/jwt_login") == 0) {
            ret = handle_jwt_login(client, buf, config.username, config.password, config.jwt_secret, config.jwt_expire, config.access_log, min_level);
        } else if (strcmp(path, "/jwt") == 0) {
            ret = handle_jwt(client, buf, config.jwt_secret, config.access_log, min_level);
        } else {
            if (strstr(path, "..")) {
                send_error_page(client, 403);
                write_log(config.access_log, min_level, LOG_WARNING, "不安全的路径访问: %s", path);
                close(client);
                continue;
            }
            char file[256];
            snprintf(file, sizeof(file), ".%s", path);
            ret = send_static_file(client, file, config.access_log, min_level);
        }
        if (is_root) {
            write_log(config.system_log, LOG_INFO, LOG_INFO, "HTTP/1.1 200 OK");
        }
        if (is_secured && is_secured_unauth) {
            write_log(config.system_log, LOG_INFO, LOG_WARNING, "HTTP/1.1 401 Unauthorized");
        }
        if (ret < 0) {
            write_log(config.system_log, min_level, LOG_WARNING, "请求处理失败: %s %s", method, path);
        }
        close(client);
    }
    close(server_sock);
    return 0;
} 
