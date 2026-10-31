cmake_minimum_required(VERSION 3.16)
project(BaaadHookEmbedTest LANGUAGES C)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../.." baaadhook)

add_executable(embed_test main.c)
target_link_libraries(embed_test PRIVATE BaaadHook::baaadhook)
