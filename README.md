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

## PLT 符号版本

```c
int bh_plt_hook_version(const char *image_name, const char *symbol,
                        const char *version, void *replacement,
                        void **original);
```

按 GNU 符号版本选择 Relocation Slot。`image_name`、`symbol`、`replacement`、
`original` 的语义与 `bh_plt_hook` 相同，`version` 额外过滤符号的版本名：

- `version == NULL`：不过滤版本，选择所有版本。`bh_plt_hook` 内部调用
  `bh_plt_hook_version(..., NULL, ...)`，行为与原来一致。
- `version == ""`：按“无版本”处理，同样不过滤，等价于 `version == NULL`。
- 非空 `version`：只匹配版本名等于该字符串的符号。没有版本名的符号
  （Versym 的 `idx == 0` 或 `idx == 1`）不匹配；Versym 表缺失、版本表
  越界或版本名无法解析时同样不匹配。
- 版本名来自目标映像的动态段：先查 `DT_VERNEED` 的 `vna_other == idx`，
  再查 `DT_VERDEF` 的 `vd_ndx == idx`，其中 `idx = versym & 0x7fff`。
- `image_name` 仍然表示 Relocation Slot 所在的映像，而不是符号的定义映像。
  例如可执行文件自身调用 `foo@VER1` / `foo@@VER2` 时，应传该可执行文件
  的路径或 `NULL`；只有要 Hook 某个 DSO 自己 PLT 中的调用时，才传该 DSO
  的名字。
- 版本过滤只作用于 Slot 选择。`original` 优先用 `dlvsym`（平台提供时）按
  同一版本名解析；`dlvsym` 不可用或解析失败时回退 `dlsym`，此时非默认版本
  可能拿到默认版本实现。
- `bh_plt_unhook` / `bh_plt_is_hooked` 没有版本参数，按 `symbol` 与
  `replacement` 匹配；对不同版本使用不同 Replacement 时可以分别 Unhook。
- PLT 扫描同时处理 `DT_RELA/DT_REL` 和 Android APS2
  （`DT_ANDROID_REL/DT_ANDROID_RELA`）中的 `GLOB_DAT`；`JUMP_SLOT` 仍走
  `DT_JMPREL`，Packed Relocation 只覆盖 GLOB_DAT。

## 并发与生命周期

- `bh_inline_hook` 与 `bh_plt_hook` 会先发布 `*original`，再让 Hook 生效。
  Replacement 必须通过该指针调用原始实现。
- `bh_inline_unhook` 只恢复入口，并把 Trampoline 移到 retired 链表，不立即释放。
  只有调用 `bh_inline_release_trampolines()` 才会真正 munmap。调用 release 前必须
  保证没有线程仍在该 Trampoline 中执行，也没有线程会再通过已保存的 `original`
  指针进入它；否则会产生 use-after-unmap。retired 未 release 前会持续占用内存，
  因此运行期反复 Hook/Unhook 后应在确认线程静默时调用 release。
- PLT 的 `original` 优先取安装前 Slot 里的当前绑定：如果它指向其它映像
  （第三方 Hook 或跨映像绑定），`*original` 就是该地址，因此可以与其它
  Hook 框架链式组合；只有 Slot 仍指向本映像的 Lazy PLT Stub（或本映像内
  定义的符号）时，才用 `dlsym` 解析真实实现。
- `bh_plt_hook` 在解析阶段之后、持锁写入之前会重新读取 Slot；如果它与解析
  阶段观察到的值不同，返回 `BH_PLT_ERROR_ALREADY_HOOKED`，不会覆盖。发现
  遗留 Record 但 Slot 已不再指向它的 Replacement 时，会先丢弃该 Record，
  再按新 Hook 处理。
- Inline 入口写入在 4 字节对齐、ARM64 BTI 前缀不变、x86_64 8 字节对齐的
  5 字节补丁等场景使用原子写；其余场景（如 2 对齐的 Thumb 目标、非 8 对齐的
  x86 入口）仍回退 `memcpy`，调用方需保证写入期间没有线程执行入口。
- Inline Hook 不识别安装前已存在的第三方入口补丁；与其它 Inline Hook 框架
  组合时可能失败或覆盖对方补丁，需要链式组合时应先自行检查入口。
- `bh_plt_is_hooked` 除匹配 Record 外，还会原子读取 Slot 并确认它仍等于
  Record 的 Replacement。第三方改写 Slot 后，`bh_plt_unhook` 与
  `bh_plt_unhook_all` 会丢弃失效 Record；只有 CAS 因内存保护失败时才保留
  Record。
- PLT 解析使用带 `RTLD_NODELETE`（平台支持时）的 `dlopen` 固定已扫描映像，
  避免写 Slot 期间映像被 `dlclose` 卸载；解析完成后仍会关闭 `dlopen` 句柄。
- 默认 `image_name == NULL` 会 Hook 所有映像中的同名 Relocation Slot，这些
  Slot 可能绑定到不同实现，调用方应按映像分别保存和使用 `original`。
- PLT 扫描与解析会调用 `dl_iterate_phdr`、`dlopen`、`dlsym` 并使用堆分配。
  不要在 DSO 构造函数里首次调用 Hook，也不要在 `malloc/free` 的 Replacement
  里调用 PLT Hook，避免 loader lock 或分配器递归。

## BTI 与代码页保护

arm64 上改写可执行页时会尽量保留 `PROT_BTI`，整体属于 best-effort：

- 判断目标页是否带 BTI 时，先查 `dl_iterate_phdr` 的 `PT_GNU_PROPERTY`
  （`GNU_PROPERTY_AARCH64_FEATURE_1_BTI`）。JIT、匿名可执行页等不属于任何
  已加载映像段的地址，回退到 `/proc/self/smaps`：找到包含该地址的映射后读
  其 `VmFlags` 行，按空格分词，出现 `bt` 标记即视为带 BTI。
- 内核可以隐藏 `VmFlags`（例如关闭 `CONFIG_PROC_PAGE_MONITOR`、受限的
  `/proc` 挂载或 SELinux 限制），此时按“无 BTI”处理。
- 写保护路径中若 `mprotect` 带 `PROT_BTI` 失败（内核不支持 BTI，或 SELinux
  拒绝带 BTI 的映射），会去掉 `PROT_BTI` 重试一次；成功则继续写入，并只
  恢复不带 BTI 的页保护，失败才向调用方报错。BTI 不受支持不会直接让 Hook
  失败。
- 上述回退意味着原页面的 BTI 标记可能被清掉；优先保证 Hook 可用，BTI 保持
  是 best-effort，需要严格 BTI 的场景应自行确认结果。

## 参考项目


- [jmpews/Dobby](https://github.com/jmpews/Dobby)
- [eirv/riscv64-inline-hook](https://github.com/eirv/riscv64-inline-hook)
- [frida/frida-gum](https://github.com/frida/frida-gum)
- [LSPosed/LSPlt](https://github.com/LSPosed/LSPlt)

## License

BaaadHook is licensed under the [MIT License](LICENSE)
