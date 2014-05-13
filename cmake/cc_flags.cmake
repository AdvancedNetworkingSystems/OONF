include(CheckCCompilerFlag)

# define a function that checks if a certain compiler flag is available
# use it if it is available, display a warning if not
function(add_compiler_flag flag)
    check_c_compiler_flag(${flag} test${flag})
    if (${test${flag}})
        ADD_DEFINITIONS(${flag})
    endif()
endfunction(add_compiler_flag)

# Make sure this file is not run again
SET(OONF_FLAGS_SET true)

# detect operation system and add missing variables for easy CMAKE OS detection
STRING(TOLOWER ${CMAKE_SYSTEM_NAME} SYSTEM_NAME)

IF (${SYSTEM_NAME} MATCHES "android" OR ANDROID)
    message("Android detected")
    SET(LINUX true)
    SET(ANDROID true)
    SET(UNIX true)
ELSEIF (${SYSTEM_NAME} MATCHES "linux")
    message("Linux detected")
    SET(LINUX true)
ENDIF (${SYSTEM_NAME} MATCHES "android" OR ANDROID)

IF (APPLE)
    message("Mac OS detected")
    set(BSD true)
ELSEIF (${SYSTEM_NAME} MATCHES "bsd")
    message("BSD detected")
    SET(BSD true)
ENDIF (APPLE)

IF (WIN32)
    message("Win32 detected")
ENDIF (WIN32)

# add build directory to include path for autogenerated files
include_directories(${CMAKE_BINARY_DIR})

# Add a compiler flag for unix systems
IF (UNIX)
    ADD_DEFINITIONS(-D__unix__)
ENDIF (UNIX)

# compiler flags that needs to be there both for API and application
IF (OONF_LOGGING_LEVEL STREQUAL "warn")
  # only display warnings, no comment necessary
ELSEIF (OONF_LOGGING_LEVEL STREQUAL "info")
  ADD_DEFINITIONS(-DOONF_LOG_INFO)
ELSEIF (OONF_LOGGING_LEVEL STREQUAL "debug")
  ADD_DEFINITIONS(-DOONF_LOG_INFO)
  ADD_DEFINITIONS(-DOONF_LOG_DEBUG_INFO)
ELSE (OONF_LOGGING_LEVEL STREQUAL "none")
  message(FATAL_ERROR "Unknown debug level '${OONF_LOGGING_LEVEL}'")
ENDIF (OONF_LOGGING_LEVEL STREQUAL "warn")

IF (OONF_REMOVE_HELPTEXT)
    ADD_DEFINITIONS(-DREMOVE_HELPTEXT)
ENDIF(OONF_REMOVE_HELPTEXT)

# OS-specific compiler settings
IF(ANDROID OR WIN32)
    # Android and windows don't compile well with c99
    ADD_DEFINITIONS(-std=gnu99)
ELSE(ANDROID OR WIN32)
    # everything else does
    ADD_DEFINITIONS(-std=c99 -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -D__BSD_VISIBLE -D_DARWIN_C_SOURCE -D__KERNEL_STRICT_NAMES)
ENDIF (ANDROID OR WIN32)

# add some necessary additions for win32
IF (WIN32)
    ADD_DEFINITIONS(-D_WIN32_WINNT=0x0502)
    SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--enable-auto-import")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--export-all-symbols")
ENDIF(WIN32)

# create all data inside the build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# set release specific compiler options
IF (NOT CMAKE_C_FLAGS) 
    ADD_DEFINITIONS(-g)
ENDIF()
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O4 -g0 -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -g0 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-DNDEBUG")

# add -Werror compiler options
IF (OONF_NO_WERROR)
	message ("Skip -Werror")
ELSE (OONF_NO_WERROR)
	ADD_DEFINITIONS(-Werror)
ENDIF (OONF_NO_WERROR)

# set compiler flags that are supported
add_compiler_flag(-finline-functions-called-once)
add_compiler_flag(-funit-at-a-time)
add_compiler_flag(-fearly-inlining)
add_compiler_flag(-fno-strict-aliasing)
add_compiler_flag(-finline-limit=350)
add_compiler_flag(-fvisibility=hidden)

add_compiler_flag(-Wall)
add_compiler_flag(-Wextra)
add_compiler_flag(-Wold-style-definition)
add_compiler_flag(-Wdeclaration-after-statement)
add_compiler_flag(-Wmissing-prototypes)
add_compiler_flag(-Wstrict-prototypes)
add_compiler_flag(-Wmissing-declarations)
add_compiler_flag(-Wsign-compare)
add_compiler_flag(-Waggregate-return)
add_compiler_flag(-Wmissing-noreturn)
add_compiler_flag(-Wmissing-format-attribute)
add_compiler_flag(-Wno-multichar)
add_compiler_flag(-Wno-deprecated-declarations)
add_compiler_flag(-Wendif-labels)
add_compiler_flag(-Wwrite-strings)
add_compiler_flag(-Wbad-function-cast)
add_compiler_flag(-Wpointer-arith)
add_compiler_flag(-Wno-cast-qual)
add_compiler_flag(-Wshadow)
add_compiler_flag(-Wsequence-point)
add_compiler_flag(-Wpointer-arith)
add_compiler_flag(-Wnested-externs)
add_compiler_flag(-Winline)
add_compiler_flag(-Wdisabled-optimization)
add_compiler_flag(-Wformat)
add_compiler_flag(-Wformat-security)
add_compiler_flag(-Wstrict-overflow=5)
add_compiler_flag(-Wdouble-promotion)
add_compiler_flag(-Wformat-y2k)
add_compiler_flag(-Wtrampolines)
add_compiler_flag(-Wlogical-op)
add_compiler_flag(-Wswitch-default)
add_compiler_flag(-Winit-self)
add_compiler_flag(-Wsync-nand)
add_compiler_flag(-Wundef)
add_compiler_flag(-Wunused-parameter)
add_compiler_flag(-Wjump-missed-init)

# check for link time optimization
# check_c_compiler_flag("-flto" test_lto)
# if (${test_lto})
#     if (NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
#         ADD_DEFINITIONS(-flto -fuse-linker-plugin)
#         SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
#         SET(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} -flto")
#     endif()
# endif()
