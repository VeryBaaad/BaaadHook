# BaaadHook

BaaadHook 是一个 Android inline / PLT hook 框架。

# ABIs

`arm64-v8a`、`armeabi-v7a`、`x86_64`、`x86`、`riscv64`

## 构建

- CMake >= 3.16
- NDK r29

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-21 \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build
```

### 引入

```cmake
add_subdirectory(external/BaaadHook)

add_library(my_native SHARED native.c)
target_link_libraries(my_native PRIVATE BaaadHook::baaadhook)
```

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `BH_BUILD_SHARED` | `OFF` | 构建共享库 |
| `BH_BUILD_TESTS` | 非交叉编译时 `ON` | 主机测试 |
| `BH_BUILD_EXAMPLES` | `ON` | 示例程序 |
| `BH_INSTALL` | `ON` | 安装 |

#### 安装后

```cmake
find_package(BaaadHook CONFIG REQUIRED)
target_link_libraries(app PRIVATE BaaadHook::baaadhook)
```

## 验证

本仓库自带的主机测试：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

## 参考项目


- [jmpews/Dobby](https://github.com/jmpews/Dobby)
- [eirv/riscv64-inline-hook](https://github.com/eirv/riscv64-inline-hook)
- [frida/frida-gum](https://github.com/frida/frida-gum)
- [LSPosed/LSPlt](https://github.com/LSPosed/LSPlt)

## License

BaaadHook is licensed under the [MIT License](LICENSE)
