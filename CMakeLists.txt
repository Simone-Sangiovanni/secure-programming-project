cmake_minimum_required(VERSION 3.21)
project(secure_programming_project C)

# Force C23 standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Export compile commands for clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find libsodium on system using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Rename binary from 'app' to 'sfm'
add_executable(sfm src/main.c)

# Include libsodium headers and link against the library
target_include_directories(sfm PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sfm PRIVATE ${SODIUM_LIBRARIES})

# Enable strict security compiler flags for GCC
target_compile_options(sfm PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wformat=2                  # Warn on format string vulnerabilities (e.g., printf(str))
    -Wshadow                    # Warn when a variable declaration shadows another
    -Wconversion                # Warn on implicit type conversions that may lose data
    -Wnull-dereference          # Warn on potential null pointer dereferences
    -Wstack-protector           # Warn if stack protection cannot be applied
    -fstack-protector-strong    # Add stack canaries to detect buffer overflows
    -D_FORTIFY_SOURCE=2         # Replace unsafe libc calls with safer checked variants at compile/run time
    -fPIE                       # Position Independent Executable (ASLR support)
)

# Enable hardening flags during linking
target_link_options(sfm PRIVATE
    -pie                        # Enable ASLR
    -Wl,-z,relro,-z,now         # Disable GOT overwriting (Full RELRO)
    -Wl,-z,noexecstack          # Prevent code execution from the stack (NX bit)
)