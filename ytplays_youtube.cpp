#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

static size_t write_to_string_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string http_post_form(const std::string& url,
                                  const std::string& form_encoded,
                                  const std::vector<std::string>& extra_headers = {}) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string resp;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, form_encoded.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // handle gzip/deflate/br

    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    for (const auto& h : extra_headers) hdrs = curl_slist_append(hdrs, h.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("curl POST failed: ") + curl_easy_strerror(res));
    }
    if (code < 200 || code >= 300) {
        throw std::runtime_error("HTTP " + std::to_string(code) + " POST " + url + "\n" + resp);
    }
    return resp;
}

static std::string http_get_json(const std::string& url, const std::string& bearer_token) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string resp;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // handle gzip/deflate/br

    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, ("Authorization: Bearer " + bearer_token).c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("curl GET failed: ") + curl_easy_strerror(res));
    }
    if (code < 200 || code >= 300) {
        throw std::runtime_error("HTTP " + std::to_string(code) + " GET " + url + "\n" + resp);
    }
    return resp;
}

static std::string url_encode_query(const std::string& s) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    char* out = curl_easy_escape(curl, s.c_str(), static_cast<int>(s.size()));
    std::string r = out ? std::string(out) : "";
    if (out) curl_free(out);
    curl_easy_cleanup(curl);
    return r;
}

static json load_json_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return json::object();
    json j;
    in >> j;
    return j;
}

static void save_json_file(const std::string& path, const json& j) {
    std::ofstream out(path, std::ios::trunc);
    out << j.dump(2);
}

static int clamp_int(int v, int lo, int hi) {
    return (std::max)(lo, (std::min)(v, hi));
}

static std::string get_env_var(const std::string& name) {
    const char* val = std::getenv(name.c_str());
    return val ? std::string(val) : "";
}

static std::string expand_percent_env_vars(const std::string& s) {
    std::string out;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] != '%') {
            out.push_back(s[i++]);
            continue;
        }

        size_t j = s.find('%', i + 1);
        if (j == std::string::npos) {
            out.append(s.substr(i));
            break;
        }

        const std::string key = s.substr(i + 1, j - i - 1);
        const std::string val = get_env_var(key);
        if (!val.empty()) out.append(val);
        else out.append(s.substr(i, j - i + 1));
        i = j + 1;
    }
    return out;
}

struct Tokens {
    std::string access_token;
    std::string refresh_token;
    int expires_in = 0;
    Clock::time_point obtained_at = Clock::now();
};

static bool token_expired_soon(const Tokens& t) {
    if (t.expires_in <= 0) return false;
    auto age = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - t.obtained_at).count();
    return age >= (t.expires_in - 60);
}

struct ScraperFallbackConfig {
    bool enable_scraper_fallback = true;
    std::unordered_set<std::string> fallback_on_reasons = {"quotaExceeded"};
    std::string scraper_node_path = "node";
    std::string scraper_script = "scraper/chat_worker.mjs";
    std::string scraper_profile_dir = "%LOCALAPPDATA%\\ytplays-profile";
    bool scraper_headless = false;
    int scraper_restart_backoff_sec = 5;
    int api_reprobe_interval_sec = 900;
};

struct AppConfig {
    std::string client_id;
    std::string client_secret;
    std::string commands_file = "C:\\ytplays\\commands.txt";
    std::string live_chat_id;
    std::string live_video_id;
    bool allow_livebroadcast_lookup = false;
    bool allowed_keys_configured = false;
    std::unordered_set<std::string> allowed_keys;
    ScraperFallbackConfig scraper;
};

// --- OAuth (device code flow) ---

static Tokens device_flow_auth(const std::string& client_id,
                               const std::string& client_secret,
                               const std::string& scope) {
    const std::string device_url = "https://oauth2.googleapis.com/device/code";
    const std::string token_url = "https://oauth2.googleapis.com/token";

    std::string form = "client_id=" + url_encode_query(client_id) +
                       "&scope=" + url_encode_query(scope);
    if (!client_secret.empty()) {
        form += "&client_secret=" + url_encode_query(client_secret);
    }

    json d = json::parse(http_post_form(device_url, form));
    const std::string device_code = d.value("device_code", "");
    const std::string user_code = d.value("user_code", "");
    const std::string verification_url = d.value("verification_url", d.value("verification_uri", ""));
    int interval = d.value("interval", 5);

    if (device_code.empty() || user_code.empty() || verification_url.empty()) {
        throw std::runtime_error("Device flow response missing fields:\n" + d.dump(2));
    }

    std::cout << "\n== YouTube Auth ==\n";
    std::cout << "1) Open: " << verification_url << "\n";
    std::cout << "2) Enter code: " << user_code << "\n";
    std::cout << "Waiting for approval...\n\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(interval));

        std::string poll_form = "client_id=" + url_encode_query(client_id);
        if (!client_secret.empty()) {
            poll_form += "&client_secret=" + url_encode_query(client_secret);
        }
        poll_form += "&device_code=" + url_encode_query(device_code);
        poll_form += "&grant_type=urn:ietf:params:oauth:grant-type:device_code";

        try {
            json t = json::parse(http_post_form(token_url, poll_form));
            Tokens tok;
            tok.access_token = t.value("access_token", "");
            tok.refresh_token = t.value("refresh_token", "");
            tok.expires_in = t.value("expires_in", 0);
            tok.obtained_at = Clock::now();

            if (tok.access_token.empty()) {
                throw std::runtime_error("No access_token in response:\n" + t.dump(2));
            }
            if (tok.refresh_token.empty()) {
                std::cerr << "Warning: no refresh_token returned (you may need to re-auth next run).\n";
            }
            return tok;
        } catch (const std::exception& e) {
            const std::string msg = e.what();
            if (msg.find("authorization_pending") != std::string::npos) continue;
            if (msg.find("slow_down") != std::string::npos) { interval += 2; continue; }
            if (msg.find("access_denied") != std::string::npos) throw;
            std::cerr << "Auth poll: " << msg << "\n";
        }
    }
}

static Tokens refresh_access_token(const std::string& client_id,
                                  const std::string& client_secret,
                                  const std::string& refresh_token) {
    const std::string token_url = "https://oauth2.googleapis.com/token";

    std::string form =
        "client_id=" + url_encode_query(client_id) +
        "&grant_type=refresh_token" +
        "&refresh_token=" + url_encode_query(refresh_token);

    if (!client_secret.empty()) {
        form += "&client_secret=" + url_encode_query(client_secret);
    }

    json t = json::parse(http_post_form(token_url, form));
    Tokens tok;
    tok.access_token = t.value("access_token", "");
    tok.refresh_token = refresh_token;
    tok.expires_in = t.value("expires_in", 0);
    tok.obtained_at = Clock::now();

    if (tok.access_token.empty()) {
        throw std::runtime_error("Refresh failed:\n" + t.dump(2));
    }
    return tok;
}

// --- YouTube Live ---

static std::string get_live_chat_id_from_video_id(const std::string& access_token,
                                                  const std::string& video_id) {
    if (video_id.empty()) return "";

    std::string url =
        "https://www.googleapis.com/youtube/v3/videos"
        "?part=liveStreamingDetails&id=" + url_encode_query(video_id);

    json j = json::parse(http_get_json(url, access_token));
    auto items_it = j.find("items");
    if (items_it == j.end() || !items_it->is_array() || items_it->empty()) return "";

    const auto& item = (*items_it)[0];
    auto details_it = item.find("liveStreamingDetails");
    if (details_it == item.end() || !details_it->is_object()) return "";
    return details_it->value("activeLiveChatId", "");
}

static std::string get_active_live_chat_id_from_broadcasts(const std::string& access_token) {
    // NOTE: Do NOT combine broadcastStatus with mine=true.
    std::string url =
        "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        "?part=snippet,status&broadcastStatus=active&maxResults=5";

    json j = json::parse(http_get_json(url, access_token));
    auto items_it = j.find("items");
    if (items_it == j.end() || !items_it->is_array() || items_it->empty()) return "";

    for (const auto& item : *items_it) {
        auto snippet_it = item.find("snippet");
        if (snippet_it == item.end() || !snippet_it->is_object()) continue;
        std::string liveChatId = snippet_it->value("liveChatId", "");
        if (!liveChatId.empty()) return liveChatId;
    }
    return "";
}

// --- Command parsing + rate limiting ---

static std::string upper_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

static std::string normalize_command_key(std::string s) {
    s = upper_ascii(std::move(s));
    while (!s.empty() && !std::isalnum(static_cast<unsigned char>(s.back()))) s.pop_back();
    while (!s.empty() && !std::isalnum(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    return s;
}

struct CommandPolicy {
    int max_per_sec = 50;
    std::chrono::milliseconds user_cooldown{0};
    int max_cmds_per_message = 50;
    int max_repeat_count = 100;
    bool enforce_allowed_keys = false;
    std::unordered_set<std::string> allowed_keys;
};

struct CommandLimiter {
    CommandPolicy policy;

    Clock::time_point window_start = Clock::now();
    int window_count = 0;

    std::unordered_map<std::string, Clock::time_point> user_last;

    bool try_consume_global() {
        auto now = Clock::now();
        if (now - window_start >= std::chrono::seconds(1)) {
            window_start = now;
            window_count = 0;
        }
        if (window_count >= policy.max_per_sec) return false;
        window_count++;
        return true;
    }

    bool user_ready(const std::string& userKey) {
        auto now = Clock::now();
        auto it = user_last.find(userKey);
        if (it != user_last.end() && (now - it->second) < policy.user_cooldown) return false;
        user_last[userKey] = now;
        return true;
    }
};

struct ParsedCommand {
    std::string key;
    int repeat_count = 1;
    bool has_explicit_count = false;
};

struct ApiErrorInfo {
    long code = 0;
    std::string reason;
    std::string message;
};

struct StreamExitInfo {
    bool non_retryable = false;
    long http_code = 0;
    std::string reason;
    std::string message;
};

static void append_command(const std::string& commands_file, const ParsedCommand& cmd) {
    std::ofstream out(commands_file, std::ios::app);
    if (!out) throw std::runtime_error("Failed to open commands file for append: " + commands_file);
    const int repeats = cmd.has_explicit_count ? cmd.repeat_count : 1;
    for (int i = 0; i < repeats; ++i) {
        out << "!" << cmd.key << "\n";
    }
    out.flush();
}

static std::vector<std::string> tokenize_message(const std::string& message) {
    std::vector<std::string> tokens;
    std::string tok;

    auto flush_tok = [&tokens, &tok]() {
        if (!tok.empty()) tokens.push_back(tok);
        tok.clear();
    };

    for (size_t i = 0; i <= message.size(); ++i) {
        char c = (i < message.size()) ? message[i] : ' ';
        if (std::isspace(static_cast<unsigned char>(c)) || c == ',' || c == ';') {
            flush_tok();
        } else {
            tok.push_back(c);
        }
    }
    return tokens;
}

static bool parse_repeat_count_token(const std::string& token, int& out_count) {
    if (token.empty()) return false;
    for (char c : token) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }

    try {
        long long v = std::stoll(token);
        const long long int_max = static_cast<long long>((std::numeric_limits<int>::max)());
        if (v <= 0 || v > int_max) return false;
        out_count = static_cast<int>(v);
        return true;
    } catch (...) {
        return false;
    }
}

static std::vector<ParsedCommand> extract_bang_commands(const std::string& message,
                                                        const CommandPolicy& policy) {
    std::vector<ParsedCommand> cmds;
    const auto tokens = tokenize_message(message);

    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::string& raw = tokens[i];
        if (raw.empty() || raw[0] != '!') continue; // only !COMMAND tokens

        const std::string key = normalize_command_key(raw.substr(1));
        if (key.empty()) continue;
        if (policy.enforce_allowed_keys && !policy.allowed_keys.count(key)) continue;

        ParsedCommand pc;
        pc.key = key;

        if ((i + 1) < tokens.size()) {
            const std::string& count_token = tokens[i + 1];
            if (count_token.empty() || count_token[0] == '!') {
                // Next token is another command; keep single-press behavior.
            } else {
                int parsed_count = 0;
                if (!parse_repeat_count_token(count_token, parsed_count)) {
                    continue; // Invalid non-command count token drops this command.
                }
                pc.has_explicit_count = true;
                pc.repeat_count = (std::min)(parsed_count, policy.max_repeat_count);
                ++i; // consume count token
            }
        }

        cmds.push_back(pc);
        if ((int)cmds.size() >= policy.max_cmds_per_message) break;
    }

    return cmds;
}

static void handle_chat_message(const std::string& author,
                                const std::string& user_key,
                                const std::string& msg,
                                const std::string& commands_file,
                                CommandLimiter& limiter) {
    if (msg.empty()) return;

    const auto cmds = extract_bang_commands(msg, limiter.policy);
    if (cmds.empty()) return;

    if (!limiter.user_ready(user_key.empty() ? author : user_key)) return;

    for (const auto& c : cmds) {
        if (!limiter.try_consume_global()) break;
        append_command(commands_file, c);
        std::cout << author << ": " << msg << "  -> !" << c.key;
        if (c.has_explicit_count) std::cout << " x" << c.repeat_count;
        std::cout << "\n";
    }
}

static ApiErrorInfo parse_api_error(const std::string& raw) {
    ApiErrorInfo info;
    if (raw.empty()) return info;

    try {
        json j = json::parse(raw);
        const json* root = &j;
        if (root->is_array() && !root->empty() && (*root)[0].is_object()) {
            root = &(*root)[0];
        }

        if (!root->is_object()) {
            return info;
        }

        auto err_it = root->find("error");
        if (err_it == root->end() || !err_it->is_object()) {
            return info;
        }

        const auto& err = *err_it;
        info.code = err.value("code", 0L);
        info.message = err.value("message", "");

        auto errors_it = err.find("errors");
        if (errors_it != err.end() && errors_it->is_array() && !errors_it->empty()) {
            const auto& first = (*errors_it)[0];
            if (first.is_object()) {
                if (info.message.empty()) info.message = first.value("message", "");
                info.reason = first.value("reason", "");
            }
        }
    } catch (...) {
        // Non-JSON payloads are ignored.
    }
    return info;
}

static ApiErrorInfo parse_api_error_from_exception_message(const std::string& msg) {
    size_t p = msg.find('\n');
    if (p == std::string::npos || p + 1 >= msg.size()) return ApiErrorInfo{};
    return parse_api_error(msg.substr(p + 1));
}

static bool is_non_retryable_stream_reason(const std::string& reason) {
    return reason == "quotaExceeded" ||
           reason == "liveChatEnded" ||
           reason == "liveChatDisabled" ||
           reason == "forbidden" ||
           reason == "insufficientPermissions";
}

static AppConfig load_app_config(const json& cfg) {
    AppConfig app;
    app.client_id = cfg.value("client_id", "");
    app.client_secret = cfg.value("client_secret", "");
    app.commands_file = cfg.value("commands_file", app.commands_file);
    app.live_chat_id = cfg.value("live_chat_id", "");
    app.live_video_id = cfg.value("live_video_id", "");
    app.allow_livebroadcast_lookup = cfg.value("allow_livebroadcast_lookup", false);

    app.scraper.enable_scraper_fallback = cfg.value("enable_scraper_fallback", true);
    app.scraper.scraper_node_path = cfg.value("scraper_node_path", app.scraper.scraper_node_path);
    app.scraper.scraper_script = cfg.value("scraper_script", app.scraper.scraper_script);
    app.scraper.scraper_profile_dir = cfg.value("scraper_profile_dir", app.scraper.scraper_profile_dir);
    app.scraper.scraper_headless = cfg.value("scraper_headless", false);
    app.scraper.scraper_restart_backoff_sec =
        clamp_int(cfg.value("scraper_restart_backoff_sec", 5), 1, 300);
    app.scraper.api_reprobe_interval_sec =
        clamp_int(cfg.value("api_reprobe_interval_sec", 900), 5, 86400);

    auto allowed_keys_it = cfg.find("allowed_keys");
    if (allowed_keys_it != cfg.end()) {
        app.allowed_keys_configured = true;
        app.allowed_keys.clear();
        if (allowed_keys_it->is_array()) {
            for (const auto& v : *allowed_keys_it) {
                if (!v.is_string()) continue;
                const std::string key = normalize_command_key(v.get<std::string>());
                if (!key.empty()) app.allowed_keys.insert(key);
            }
        }
    }

    auto reasons_it = cfg.find("fallback_on_reasons");
    if (reasons_it != cfg.end() && reasons_it->is_array()) {
        app.scraper.fallback_on_reasons.clear();
        for (const auto& v : *reasons_it) {
            if (v.is_string()) {
                const std::string r = v.get<std::string>();
                if (!r.empty()) app.scraper.fallback_on_reasons.insert(r);
            }
        }
        if (app.scraper.fallback_on_reasons.empty()) {
            app.scraper.fallback_on_reasons.insert("quotaExceeded");
        }
    }

    app.scraper.scraper_profile_dir = expand_percent_env_vars(app.scraper.scraper_profile_dir);
    return app;
}

// --- Streaming JSON parsing (multiple responses on one connection) ---

struct StreamState {
    std::string buf;
    std::string raw;
    std::string lastNextPageToken;

    std::string commands_file;
    CommandLimiter* limiter = nullptr;
};

static bool try_extract_one_json(std::string& s, std::string& out) {
    size_t start = s.find('{');
    if (start == std::string::npos) {
        s.clear();
        return false;
    }

    int depth = 0;
    bool in_str = false;
    bool esc = false;

    for (size_t i = start; i < s.size(); ++i) {
        char c = s[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
        } else {
            if (c == '"') in_str = true;
            else if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    out = s.substr(start, i - start + 1);
                    s.erase(0, i + 1);
                    return true;
                }
            }
        }
    }

    if (start > 0) s.erase(0, start);
    return false;
}

static void process_stream_payload(const json& j, StreamState& st) {
    auto next_it = j.find("nextPageToken");
    if (next_it != j.end() && next_it->is_string()) {
        st.lastNextPageToken = next_it->get<std::string>();
    }

    auto items_it = j.find("items");
    if (items_it == j.end() || !items_it->is_array()) return;

    for (const auto& item : *items_it) {
        auto snippet_it = item.find("snippet");
        auto author_it = item.find("authorDetails");
        if (snippet_it == item.end() || author_it == item.end()) continue;
        if (!snippet_it->is_object() || !author_it->is_object()) continue;

        const std::string msg = snippet_it->value("displayMessage", "");
        const std::string author = author_it->value("displayName", "");
        const std::string userKey = author_it->value("channelId", author);
        handle_chat_message(author, userKey, msg, st.commands_file, *st.limiter);
    }
}

static size_t stream_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* st = static_cast<StreamState*>(userdata);
    const size_t n = size * nmemb;
    st->raw.append(ptr, n);
    if (st->raw.size() > 131072) {
        st->raw.erase(0, st->raw.size() - 131072);
    }
    st->buf.append(ptr, n);

    std::string one;
    while (try_extract_one_json(st->buf, one)) {
        try {
            const json j = json::parse(one);
            process_stream_payload(j, *st);
        } catch (...) {
            // Ignore malformed fragments; keep buffering.
        }
    }
    return size * nmemb;
}

#ifdef _WIN32
struct ChildProcessWin {
    HANDLE process = nullptr;
    HANDLE stdout_read = nullptr;

    void cleanup() {
        if (stdout_read) {
            CloseHandle(stdout_read);
            stdout_read = nullptr;
        }
        if (process) {
            CloseHandle(process);
            process = nullptr;
        }
    }

    ~ChildProcessWin() {
        terminate();
    }

    bool start(const std::string& command_line) {
        terminate();

        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE out_read = nullptr;
        HANDLE out_write = nullptr;
        if (!CreatePipe(&out_read, &out_write, &sa, 0)) {
            return false;
        }
        if (!SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(out_read);
            CloseHandle(out_write);
            return false;
        }

        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = out_write;
        si.hStdError = out_write;

        PROCESS_INFORMATION pi{};
        std::vector<char> cmd(command_line.begin(), command_line.end());
        cmd.push_back('\0');

        BOOL ok = CreateProcessA(
            nullptr,
            cmd.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi
        );

        CloseHandle(out_write);
        if (!ok) {
            CloseHandle(out_read);
            return false;
        }

        CloseHandle(pi.hThread);
        process = pi.hProcess;
        stdout_read = out_read;
        return true;
    }

    bool is_running() const {
        if (!process) return false;
        DWORD rc = WaitForSingleObject(process, 0);
        return rc == WAIT_TIMEOUT;
    }

    void terminate() {
        if (process && is_running()) {
            TerminateProcess(process, 1);
            WaitForSingleObject(process, 3000);
        }
        cleanup();
    }

    bool read_stdout_chunk(std::string& out) {
        if (!stdout_read) return false;

        DWORD avail = 0;
        if (!PeekNamedPipe(stdout_read, nullptr, 0, nullptr, &avail, nullptr)) {
            return false;
        }
        if (avail == 0) return false;

        char buf[4096];
        DWORD to_read = (std::min)(avail, static_cast<DWORD>(sizeof(buf)));
        DWORD n = 0;
        if (!ReadFile(stdout_read, buf, to_read, &n, nullptr) || n == 0) {
            return false;
        }

        out.append(buf, n);
        return true;
    }
};
#endif

static std::string quote_cmd_arg(const std::string& s) {
    if (s.empty()) return "\"\"";
    bool needs_quotes = false;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == '"') {
            needs_quotes = true;
            break;
        }
    }
    if (!needs_quotes) return s;

    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else out.push_back(c);
    }
    out += "\"";
    return out;
}

static StreamExitInfo run_live_chat_stream(Tokens& tok,
                                           const std::string& client_id,
                                           const std::string& client_secret,
                                           const std::string& token_path,
                                           const std::string& liveChatId,
                                           const std::string& commands_file,
                                           CommandLimiter& limiter) {
    std::string pageToken;
    int backoff_sec = 1;

    while (true) {
        if (token_expired_soon(tok) && !tok.refresh_token.empty()) {
            tok = refresh_access_token(client_id, client_secret, tok.refresh_token);
            save_json_file(token_path, json{
                {"access_token", tok.access_token},
                {"refresh_token", tok.refresh_token},
                {"expires_in", tok.expires_in}
            });
            std::cout << "Token refreshed.\n";
        }

        StreamState st;
        st.commands_file = commands_file;
        st.limiter = &limiter;
        st.lastNextPageToken = pageToken;

        std::string url =
            "https://www.googleapis.com/youtube/v3/liveChat/messages/stream"
            "?part=snippet,authorDetails"
            "&liveChatId=" + url_encode_query(liveChatId) +
            "&maxResults=500";
        if (!pageToken.empty()) {
            url += "&pageToken=" + url_encode_query(pageToken);
        }

        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl_easy_init failed");

        struct curl_slist* hdrs = nullptr;
        hdrs = curl_slist_append(hdrs, ("Authorization: Bearer " + tok.access_token).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &st);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 15L);

        CURLcode res = curl_easy_perform(curl);

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);

        if (!st.lastNextPageToken.empty()) pageToken = st.lastNextPageToken;

        if (res == CURLE_OK && http_code >= 200 && http_code < 300) {
            backoff_sec = 1;
        } else {
            const ApiErrorInfo api_err = parse_api_error(st.raw);
            std::cerr << "Stream disconnected (curl=" << curl_easy_strerror(res)
                      << ", http=" << http_code << ").";
            if (!api_err.reason.empty() || !api_err.message.empty()) {
                std::cerr << " reason=" << (api_err.reason.empty() ? "unknown" : api_err.reason);
                if (!api_err.message.empty()) std::cerr << " message=" << api_err.message;
            }

            if (is_non_retryable_stream_reason(api_err.reason)) {
                std::cerr << " Non-retryable API error; stopping.\n";
                StreamExitInfo exit;
                exit.non_retryable = true;
                exit.http_code = http_code;
                exit.reason = api_err.reason;
                exit.message = api_err.message;
                return exit;
            }

            std::cerr << " Reconnecting...\n";
            backoff_sec = (std::min)(backoff_sec * 2, 30);
        }

        std::this_thread::sleep_for(std::chrono::seconds(backoff_sec));
    }

    return StreamExitInfo{};
}

static void refresh_token_if_needed(Tokens& tok,
                                    const std::string& client_id,
                                    const std::string& client_secret,
                                    const std::string& token_path) {
    if (token_expired_soon(tok) && !tok.refresh_token.empty()) {
        tok = refresh_access_token(client_id, client_secret, tok.refresh_token);
        save_json_file(token_path, json{
            {"access_token", tok.access_token},
            {"refresh_token", tok.refresh_token},
            {"expires_in", tok.expires_in}
        });
        std::cout << "Token refreshed.\n";
    }
}

static bool probe_live_chat_api(Tokens& tok,
                                const std::string& client_id,
                                const std::string& client_secret,
                                const std::string& token_path,
                                const std::string& liveChatId,
                                std::string& out_reason,
                                std::string& out_message) {
    out_reason.clear();
    out_message.clear();

    refresh_token_if_needed(tok, client_id, client_secret, token_path);

    const std::string url =
        "https://www.googleapis.com/youtube/v3/liveChat/messages"
        "?part=id"
        "&liveChatId=" + url_encode_query(liveChatId) +
        "&maxResults=1";

    try {
        (void)http_get_json(url, tok.access_token);
        return true;
    } catch (const std::exception& e) {
        const std::string err = e.what();
        const ApiErrorInfo parsed = parse_api_error_from_exception_message(err);
        out_reason = parsed.reason;
        out_message = parsed.message.empty() ? err : parsed.message;
        return false;
    }
}

static std::string build_scraper_worker_cmdline(const AppConfig& app) {
    std::string cmd = quote_cmd_arg(app.scraper.scraper_node_path);
    cmd += " " + quote_cmd_arg(app.scraper.scraper_script);
    cmd += " --video-id " + quote_cmd_arg(app.live_video_id);
    cmd += " --profile-dir " + quote_cmd_arg(app.scraper.scraper_profile_dir);
    cmd += " --headless " + std::string(app.scraper.scraper_headless ? "true" : "false");
    return cmd;
}

static void process_scraper_event_line(const std::string& line,
                                       const std::string& commands_file,
                                       CommandLimiter& limiter) {
    if (line.empty()) return;

    json evt;
    try {
        evt = json::parse(line);
    } catch (...) {
        std::cerr << "Scraper emitted non-JSON line: " << line << "\n";
        return;
    }

    const std::string type = evt.value("type", "");
    if (type == "chat") {
        const std::string author = evt.value("author", "YouTubeChat");
        const std::string user_key = evt.value("userKey", author);
        const std::string message = evt.value("message", "");
        handle_chat_message(author, user_key, message, commands_file, limiter);
        return;
    }

    if (type == "status") {
        const std::string state = evt.value("state", "unknown");
        if (state == "heartbeat") return;
        std::cout << "[scraper] status=" << state;
        const std::string detail = evt.value("detail", "");
        if (!detail.empty()) std::cout << " detail=" << detail;
        std::cout << "\n";
        if (state == "chat_disabled" || state == "chat_ended") {
            throw std::runtime_error("scraper reported terminal state: " + state);
        }
        return;
    }

    if (type == "error") {
        std::cerr << "[scraper] error reason=" << evt.value("reason", "unknown")
                  << " message=" << evt.value("message", "") << "\n";
        return;
    }

    if (type == "ready") {
        std::cout << "[scraper] ready\n";
        return;
    }

    std::cout << "[scraper] event=" << line << "\n";
}

static void run_scraper_fallback_loop(Tokens& tok,
                                      const AppConfig& app,
                                      const std::string& token_path,
                                      const std::string& liveChatId,
                                      CommandLimiter& limiter) {
#ifndef _WIN32
    (void)tok; (void)app; (void)token_path; (void)liveChatId; (void)limiter;
    throw std::runtime_error("scraper fallback requires Windows in this build");
#else
    if (app.live_video_id.empty()) {
        throw std::runtime_error("scraper fallback requires live_video_id in config.json");
    }
    {
        std::ifstream in(app.scraper.scraper_script);
        if (!in) {
            throw std::runtime_error("scraper script not found: " + app.scraper.scraper_script);
        }
    }

    const std::string cmdline = build_scraper_worker_cmdline(app);
    std::cout << "Switching to scraper fallback mode.\n";
    std::cout << "[scraper] command: " << cmdline << "\n";

    int consecutive_probe_successes = 0;
    int backoff_sec = app.scraper.scraper_restart_backoff_sec;
    auto next_probe_at = Clock::now() + std::chrono::seconds(app.scraper.api_reprobe_interval_sec);

    while (true) {
        ChildProcessWin proc;
        if (!proc.start(cmdline)) {
            throw std::runtime_error("failed to start scraper worker process");
        }

        std::string read_buf;
        auto last_event_at = Clock::now();
        bool should_restart = false;

        while (proc.is_running()) {
            std::string chunk;
            bool saw_output = false;
            while (proc.read_stdout_chunk(chunk)) {
                saw_output = true;
            }

            if (saw_output) {
                backoff_sec = app.scraper.scraper_restart_backoff_sec;
                read_buf.append(chunk);
                size_t pos = 0;
                while (true) {
                    size_t nl = read_buf.find('\n', pos);
                    if (nl == std::string::npos) {
                        read_buf.erase(0, pos);
                        break;
                    }
                    std::string line = read_buf.substr(pos, nl - pos);
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    pos = nl + 1;
                    if (line.empty()) continue;

                    last_event_at = Clock::now();
                    process_scraper_event_line(line, app.commands_file, limiter);
                }
            }

            const auto now = Clock::now();

            if ((now - last_event_at) > std::chrono::seconds(120)) {
                std::cerr << "[scraper] no events for 120s; restarting worker.\n";
                should_restart = true;
                break;
            }

            if (now >= next_probe_at) {
                std::string probe_reason;
                std::string probe_message;
                const bool probe_ok = probe_live_chat_api(
                    tok, app.client_id, app.client_secret, token_path, liveChatId, probe_reason, probe_message
                );

                if (probe_ok) {
                    consecutive_probe_successes++;
                    std::cout << "[scraper] API probe success (" << consecutive_probe_successes << "/2)\n";
                    if (consecutive_probe_successes >= 2) {
                        std::cout << "API recovered; switching back to API stream mode.\n";
                        proc.terminate();
                        return;
                    }
                } else {
                    consecutive_probe_successes = 0;
                    std::cerr << "[scraper] API probe failed";
                    if (!probe_reason.empty()) std::cerr << " reason=" << probe_reason;
                    if (!probe_message.empty()) std::cerr << " message=" << probe_message;
                    std::cerr << "\n";
                }

                next_probe_at = now + std::chrono::seconds(app.scraper.api_reprobe_interval_sec);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }

        if (!proc.is_running()) {
            std::cerr << "[scraper] worker exited. restarting...\n";
            should_restart = true;
        }

        proc.terminate();
        if (!should_restart) continue;

        std::this_thread::sleep_for(std::chrono::seconds(backoff_sec));
        backoff_sec = (std::min)(backoff_sec * 2, 60);
    }
#endif
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    try {
        const std::string token_path = "token.json";

        json cfg_json = load_json_file("config.json");
        AppConfig app = load_app_config(cfg_json);

        if (app.client_id.empty()) {
            std::cerr << "Missing client_id in config.json\n";
            return 1;
        }

        const std::string scope = "https://www.googleapis.com/auth/youtube.readonly";

        Tokens tok;
        json saved = load_json_file("token.json");
        auto refresh_it = saved.find("refresh_token");
        if (refresh_it != saved.end() && refresh_it->is_string()) {
            tok.refresh_token = refresh_it->get<std::string>();
        }

        if (tok.refresh_token.empty()) {
            tok = device_flow_auth(app.client_id, app.client_secret, scope);
        } else {
            tok = refresh_access_token(app.client_id, app.client_secret, tok.refresh_token);
        }

        save_json_file(token_path, json{
            {"access_token", tok.access_token},
            {"refresh_token", tok.refresh_token},
            {"expires_in", tok.expires_in}
        });

        std::cout << "Auth OK.\n";

        std::string liveChatId;
        if (!app.live_chat_id.empty()) {
            liveChatId = app.live_chat_id;
            std::cout << "Using live_chat_id from config.\n";
        } else if (!app.live_video_id.empty()) {
            liveChatId = get_live_chat_id_from_video_id(tok.access_token, app.live_video_id);
            if (liveChatId.empty()) {
                std::cerr << "Could not resolve activeLiveChatId from live_video_id.\n";
                return 1;
            }
            std::cout << "Resolved liveChatId from live_video_id.\n";
        } else if (app.allow_livebroadcast_lookup) {
            liveChatId = get_active_live_chat_id_from_broadcasts(tok.access_token);
            std::cout << "Resolved liveChatId via liveBroadcasts fallback.\n";
        } else {
            std::cerr
                << "Missing live_chat_id/live_video_id in config.json.\n"
                << "Set one to avoid quota-heavy liveBroadcasts discovery.\n"
                << "Optional legacy fallback: allow_livebroadcast_lookup=true\n";
            return 1;
        }

        if (liveChatId.empty()) {
            std::cerr << "No liveChatId available.\n";
            return 1;
        }
        std::cout << "liveChatId: " << liveChatId << "\n";

        CommandLimiter limiter;
        limiter.policy = CommandPolicy{};
        limiter.policy.enforce_allowed_keys = app.allowed_keys_configured;
        limiter.policy.allowed_keys = app.allowed_keys;

        if (limiter.policy.enforce_allowed_keys) {
            std::cout << "Command key whitelist: restricted ("
                      << limiter.policy.allowed_keys.size()
                      << " configured key(s)).\n";
        } else {
            std::cout << "Command key whitelist: unrestricted (all keys accepted).\n";
        }

        if (app.scraper.enable_scraper_fallback && app.live_video_id.empty()) {
            std::cerr << "Warning: scraper fallback enabled but live_video_id is empty. "
                         "Fallback cannot start without live_video_id.\n";
        }

        std::cout << "Mode: api\n";
        while (true) {
            StreamExitInfo exit = run_live_chat_stream(
                tok,
                app.client_id,
                app.client_secret,
                token_path,
                liveChatId,
                app.commands_file,
                limiter
            );

            if (!exit.non_retryable) continue;

            if (app.scraper.enable_scraper_fallback &&
                !app.live_video_id.empty() &&
                app.scraper.fallback_on_reasons.count(exit.reason) > 0) {
                std::cout << "Mode: scraper_fallback\n";
                run_scraper_fallback_loop(tok, app, token_path, liveChatId, limiter);
                std::cout << "Mode: api\n";
                continue;
            }

            throw std::runtime_error(
                "liveChat stream failed with non-retryable error reason=" + exit.reason +
                " message=" + exit.message
            );
        }

    } catch (const std::exception& e) {
        const std::string err = e.what();
        std::cerr << "\nERROR: " << err << "\n";
        if (err.find("quotaExceeded") != std::string::npos) {
            std::cerr
                << "Tip: your YouTube Data API project quota is exhausted.\n"
                << "Reduce retries, wait for quota reset, or request higher quota in Google Cloud Console.\n";
        }
        return 1;
    }

    curl_global_cleanup();
    return 0;
}
