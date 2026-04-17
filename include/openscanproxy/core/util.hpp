#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace openscanproxy::core {

// 去除字符串首尾空白
std::string trim(const std::string& s);
// 按分隔符拆分字符串
std::vector<std::string> split(const std::string& s, char delim);
// 将字符串转为小写（原地修改后返回）
std::string to_lower(std::string s);
// 计算字节序列的 SHA-256 哈希，返回十六进制字符串
std::string sha256_hex(const std::vector<uint8_t>& bytes);
// 获取当前时间的 ISO 8601 格式字符串（UTC）
std::string now_iso8601();
// JSON 字符串转义（处理引号、反斜杠、换行等特殊字符）
std::string json_escape(const std::string& in);

// 最小化 JSON 对象解析器，支持扁平 key->(string|number|bool) 结构
std::map<std::string, std::string> parse_simple_json_object(const std::string& text);

}  // namespace openscanproxy::core
