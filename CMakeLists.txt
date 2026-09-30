cmake_minimum_required(VERSION 3.21)
project(secure_programming_project C)

# ---------------------------------------------------------------------------
# Language standard
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)          # -std=c23 instead of -std=gnu23

# compile_commands.json is written to build/ and consumed by clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Build type and options
# ---------------------------------------------------------------------------
# Default to Debug when no build type is given (single-config generators)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 Debug Release RelWithDebInfo MinSizeRel)
endif()

option(ENABLE_SANITIZERS   "Enable ASan + UBSan in Debug builds" ON)
option(WARNINGS_AS_ERRORS  "Treat compiler warnings as errors"   OFF)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
# Add every new source file here
set(SFM_SOURCES
    src/main.c
)

add_executable(sfm ${SFM_SOURCES})
target_link_libraries(sfm PRIVATE PkgConfig::SODIUM)

# Position Independent Executable (ASLR). With CMake >= 3.14 (policy CMP0083,
# enabled by the minimum version above) this adds both -fPIE and -pie.
include(CheckPIESupported)
check_pie_supported(LANGUAGES C)
set_target_properties(sfm PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Uncomment if strict ISO mode (extensions OFF) hides POSIX functions
# such as getline() or fileno():
# target_compile_definitions(sfm PRIVATE _POSIX_C_SOURCE=200809L)

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------
target_compile_options(sfm PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wformat=2                  # printf-style checks incl. -Wformat-security
    -Wformat-signedness         # %d vs unsigned mismatches
    -Wshadow                    # local variable hides another declaration
    -Wconversion                # implicit conversions that may lose data
    -Wnull-dereference          # most effective with optimization (-O2)
    -Wcast-qual                 # casts that drop const/volatile
    -Wvla                       # variable-length arrays (stack exhaustion)
    -Wmissing-prototypes        # non-static functions without a prototype
    -Wstack-protector           # warn if a stack canary cannot be applied
)

if(WARNINGS_AS_ERRORS)
    target_compile_options(sfm PRIVATE -Werror)
endif()

# ---------------------------------------------------------------------------
# Hardening (compiler flags are probed so unsupported ones are skipped,
# e.g. -fcf-protection does not exist on ARM)
# ---------------------------------------------------------------------------
include(CheckCCompilerFlag)

set(HARDENING_FLAGS
    -fstack-protector-strong    # stack canaries against buffer overflows
    -fstack-clash-protection    # guard against stack clash attacks
    -fcf-protection=full        # Intel CET: shadow stack + indirect branch tracking
    -fno-plt                    # resolve calls via GOT, works well with Full RELRO
)

foreach(flag IN LISTS HARDENING_FLAGS)
    string(MAKE_C_IDENTIFIER "HAVE${flag}" flag_var)
    check_c_compiler_flag("${flag}" ${flag_var})
    if(${flag_var})
        target_compile_options(sfm PRIVATE ${flag})
    endif()
endforeach()

# _FORTIFY_SOURCE needs optimization, so it is skipped in Debug builds.
# Level 3 needs GCC >= 12 / Clang and glibc >= 2.34; level 2 otherwise.
# -U first: many distros predefine _FORTIFY_SOURCE and redefining warns.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 12)
    set(FORTIFY_LEVEL 2)
else()
    set(FORTIFY_LEVEL 3)
endif()

target_compile_options(sfm PRIVATE
    $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>
    $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=${FORTIFY_LEVEL}>
)

# Linker hardening (Linux / ELF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(sfm PRIVATE
        -Wl,-z,relro,-z,now     # Full RELRO: GOT read-only after startup
        -Wl,-z,noexecstack      # non-executable stack (NX)
    )
endif()

# ---------------------------------------------------------------------------
# Sanitizers (Debug only): catch memory errors and UB at runtime
# ---------------------------------------------------------------------------
if(ENABLE_SANITIZERS)
    target_compile_options(sfm PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
        $<$<CONFIG:Debug>:-fno-sanitize-recover=undefined>
    )
    target_link_options(sfm PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
endif()