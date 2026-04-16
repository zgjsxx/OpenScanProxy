# 构建与测试脚本说明

## 概述

项目根目录新增了两个辅助脚本：

- [build.sh](../build.sh)
- [test.sh](../test.sh)

目标是把常见的 CMake 配置、编译和测试流程收敛成更稳定的命令入口，减少每次手工输入长命令的成本。

## 前提

在 Linux/macOS 上首次使用前，建议先赋予执行权限：

```bash
chmod +x build.sh test.sh
```

脚本默认假设以下工具已经安装并可用：

- `cmake`
- `ctest`
- `c++` / 系统可用的 C++ 编译器
- OpenSSL 开发库

## build.sh

### 作用

`build.sh` 负责：

1. 配置 CMake
2. 编译目标
3. 按需执行测试

### 默认行为

直接执行：

```bash
./build.sh
```

等价于：

- 使用 `build/` 作为构建目录
- 使用 `Debug` 构建
- 打开 `BUILD_TESTING=ON`
- 只编译，不自动运行测试

### 常用参数

- `--debug`
  - 使用 `Debug` 构建
- `--release`
  - 使用 `Release` 构建
- `--build-dir <dir>`
  - 指定构建目录
- `--tests`
  - 启用测试目标构建
- `--no-tests`
  - 禁用测试目标构建
- `--run-tests`
  - 编译完成后自动执行 `ctest`
- `--clean`
  - 配置前先删除构建目录
- `--verbose`
  - 输出更详细的编译信息
- `--target <name>`
  - 只编译指定目标
- `--generator <name>`
  - 指定 CMake generator
- `-j, --jobs <n>`
  - 指定并行编译线程数
- `--cmake-arg <arg>`
  - 追加额外的 CMake configure 参数

### 常用示例

#### 1. 默认调试构建

```bash
./build.sh
```

#### 2. Release 构建并运行测试

```bash
./build.sh --release --run-tests
```

#### 3. 使用独立目录做测试构建

```bash
./build.sh --build-dir build-test --run-tests
```

#### 4. 只构建主程序

```bash
./build.sh --target openscanproxy
```

#### 5. 禁用测试目标

```bash
./build.sh --no-tests
```

这会把 `BUILD_TESTING` 设为 `OFF`，测试可执行文件不会被生成。

#### 6. 使用 Ninja

```bash
./build.sh --generator Ninja
```

## test.sh

### 作用

`test.sh` 是一个更轻量的测试入口，适合在已完成构建后重复运行测试。

它会：

- 进入指定构建目录
- 在该目录内执行 `ctest`

### 默认行为

```bash
./test.sh
```

默认会在 `build/` 目录中执行：

```bash
ctest --output-on-failure
```

### 常用参数

- `--build-dir <dir>`
  - 指定构建目录
- `--verbose`
  - 使用 `ctest -VV`
- `--list`
  - 只列出测试，不执行
- `--regex <expr>`
  - 只执行匹配表达式的测试

### 常用示例

#### 1. 运行全部测试

```bash
./test.sh
```

#### 2. 列出当前注册的测试

```bash
./test.sh --list --verbose
```

#### 3. 只运行 HTTP 相关测试

```bash
./test.sh --regex http
```

#### 4. 在自定义构建目录中运行测试

```bash
./test.sh --build-dir build-test
```

## 推荐工作流

### 开发阶段

```bash
./build.sh --run-tests
```

### 做一次干净的发布构建

```bash
./build.sh --clean --release --build-dir build-release
```

### 单独重复执行测试

```bash
./test.sh
```

## 关于 CTest 的注意事项

当前环境下，建议优先使用以下方式运行测试：

```bash
./test.sh
```

或者手工进入构建目录后执行：

```bash
cd build
ctest --output-on-failure
```

原因是某些环境里直接使用：

```bash
ctest --test-dir build
```

可能表现异常，出现测试已注册但 `ctest` 显示 `No tests were found` 的情况。

本项目已经确认：

- `build/CTestTestfile.cmake` 正常生成
- 进入 `build/` 目录执行 `ctest` 可以正确识别测试

因此推荐统一通过 `test.sh` 或在构建目录内直接执行 `ctest`。

### Ubuntu 20.04.6 LTS 上的 CMake 版本问题

在 Ubuntu 20.04.6 LTS 自带的较老 CMake / CTest 环境中，已经出现过下面这种现象：

- `build/CTestTestfile.cmake` 已经正常生成
- 在 `build/` 目录内执行 `ctest` 可以正确识别测试
- 但直接执行：

```bash
ctest --test-dir build
```

却仍然显示：

```text
No tests were found!!!
```

如果你确认遇到的是系统自带旧版 CMake/CTest 的兼容性问题，建议直接升级到 Kitware 官方 APT 源提供的新版 CMake。

#### 1. 安装基础依赖

```bash
sudo apt update
sudo apt install -y ca-certificates gpg wget
```

#### 2. 导入 Kitware 仓库签名 key

```bash
test -f /usr/share/doc/kitware-archive-keyring/copyright || \
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | \
gpg --dearmor - | \
sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
```

#### 3. 添加 Ubuntu 20.04 的 Kitware 源

```bash
echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ focal main' | \
sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null
```

Kitware 官方页面给出的 Ubuntu 20.04 仓库名就是：

```text
focal main
```

#### 4. 更新索引并安装 keyring

```bash
sudo apt update
sudo apt install -y kitware-archive-keyring
```

#### 5. 安装新版 CMake

```bash
sudo apt install -y cmake
```

#### 6. 确认版本

```bash
cmake --version
ctest --version
cpack --version
```

如果升级后 `ctest --test-dir build` 行为恢复正常，可以继续使用该写法；否则仍然建议优先使用：

```bash
./test.sh
```

或者：

```bash
cd build
ctest --output-on-failure
```

## 当前测试目标

在 `BUILD_TESTING=ON` 时，目前会构建并注册以下测试：

- `http_message_test`
- `http_protocol_test`
- `policy_test`

## 相关文件

- [CMakeLists.txt](../CMakeLists.txt)
- [build.sh](../build.sh)
- [test.sh](../test.sh)
- [tests/http_message_test.cpp](../tests/http_message_test.cpp)
- [tests/http_protocol_test.cpp](../tests/http_protocol_test.cpp)
- [tests/policy_test.cpp](../tests/policy_test.cpp)
