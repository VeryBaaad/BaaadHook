cmake_minimum_required(VERSION 3.16)

project(BaaadHook VERSION 1.0.0 LANGUAGES C)

include(GNUInstallDirs)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(BH_TOP_LEVEL ON)
else()
    set(BH_TOP_LEVEL OFF)
endif()

option(BH_BUILD_SHARED "Build BaaadHook as a shared library" OFF)
option(BH_BUILD_TESTS "Build BaaadHook tests" ${BH_TOP_LEVEL})
option(BH_BUILD_EXAMPLES "Build BaaadHook examples" ${BH_TOP_LEVEL})
option(BH_INSTALL "Enable install rules (top-level builds only)" ${BH_TOP_LEVEL})

if(CMAKE_CROSSCOMPILING)
    set(BH_BUILD_TESTS OFF CACHE BOOL "Build BaaadHook tests" FORCE)
endif()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" BH_PROCESSOR_LOWER)

if(BH_PROCESSOR_LOWER MATCHES "^(aarch64|arm64|arm64-v8a)$")
    set(BH_ARCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/arch/bh_arch_arm64.c")
    set(BH_ARCH_NAME "arm64-v8a")
elseif(BH_PROCESSOR_LOWER MATCHES "^(arm|armv7|armv7-a|armv7a|armeabi-v7a)$")
    set(BH_ARCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/arch/bh_arch_arm32.c")
    set(BH_ARCH_NAME "armeabi-v7a")
elseif(BH_PROCESSOR_LOWER MATCHES "^(x86_64|amd64|x64)$")
    set(BH_ARCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/arch/bh_arch_x86.c")
    set(BH_ARCH_NAME "x86_64")
elseif(BH_PROCESSOR_LOWER MATCHES "^(i[3-6]86|x86)$")
    set(BH_ARCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/arch/bh_arch_x86.c")
    set(BH_ARCH_NAME "x86")
elseif(BH_PROCESSOR_LOWER MATCHES "^(riscv64|riscv64-v?)$")
    set(BH_ARCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/arch/bh_arch_riscv64.c")
    set(BH_ARCH_NAME "riscv64")
else()
    message(FATAL_ERROR "BaaadHook: unsupported processor '${CMAKE_SYSTEM_PROCESSOR}'")
endif()

set(BH_SOURCES
    src/bh_memory.c
    src/bh_inline.c
    src/bh_plt.c
    ${BH_ARCH_SOURCE}
)

if(BH_BUILD_SHARED)
    add_library(baaadhook SHARED ${BH_SOURCES})
else()
    add_library(baaadhook STATIC ${BH_SOURCES})
endif()

add_library(BaaadHook::baaadhook ALIAS baaadhook)
add_library(baaadhook::baaadhook ALIAS baaadhook)

set_target_properties(baaadhook PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME baaadhook
)

target_include_directories(baaadhook
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(baaadhook PRIVATE c_std_11)
target_compile_definitions(baaadhook PRIVATE BH_BUILDING_LIBRARY=1)

find_package(Threads REQUIRED)
target_link_libraries(baaadhook PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

message(STATUS "[BaaadHook] architecture: ${BH_ARCH_NAME}")
message(STATUS "[BaaadHook] library type: ${BH_BUILD_SHARED}")

if(BH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BH_INSTALL AND BH_TOP_LEVEL)
    include(CMakePackageConfigHelpers)

    install(TARGETS baaadhook
        EXPORT BaaadHookTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
    install(FILES include/bhinline.h include/bhplt.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
    install(EXPORT BaaadHookTargets
        FILE BaaadHookTargets.cmake
        NAMESPACE BaaadHook::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BaaadHook
    )

    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/BaaadHookConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/BaaadHookConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BaaadHook
    )
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/BaaadHookConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/BaaadHookConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/BaaadHookConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BaaadHook
    )
endif()
