add_library(bh_test_targets OBJECT test_inline_targets.c)
target_compile_options(bh_test_targets PRIVATE -O2 -fno-omit-frame-pointer)

add_executable(bh_inline_test test_inline.c $<TARGET_OBJECTS:bh_test_targets>)
target_link_libraries(bh_inline_test PRIVATE baaadhook)
target_compile_options(bh_inline_test PRIVATE -O0 -fno-omit-frame-pointer)
add_test(NAME bh_inline_test COMMAND bh_inline_test)

add_executable(bh_plt_test test_plt.c)
target_link_libraries(bh_plt_test PRIVATE baaadhook)
target_compile_options(bh_plt_test PRIVATE -O0 -fno-omit-frame-pointer)
add_test(NAME bh_plt_test COMMAND bh_plt_test)

if(NOT ANDROID AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_executable(bh_plt_nopie_test test_plt.c)
    target_link_libraries(bh_plt_nopie_test PRIVATE baaadhook)
    target_compile_options(bh_plt_nopie_test PRIVATE -O0 -fno-omit-frame-pointer -fno-pie)
    target_link_options(bh_plt_nopie_test PRIVATE -no-pie)
    add_test(NAME bh_plt_nopie_test COMMAND bh_plt_nopie_test)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$" AND
   CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(bh_test_targets PRIVATE -fcf-protection=branch)
    target_compile_options(bh_inline_test PRIVATE -fcf-protection=branch)
endif()
