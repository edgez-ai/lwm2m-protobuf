# ESP-IDF Component CMakeLists.txt for lwm2m-protobuf

# Check if this is being built as an ESP-IDF component
if(DEFINED IDF_PATH)
    # ESP-IDF component build using modern idf_component_register
    idf_component_register(
        SRCS 
            "src/lwm2m.pb.c"
            "src/lwm2m_helpers.c"
        INCLUDE_DIRS 
            "include"
        REQUIRES 
            nanopb 
            mbedtls
    )
    
    # Set C standard for ESP-IDF
    target_compile_features(${COMPONENT_LIB} PRIVATE c_std_99)
    
else()
    # Standalone build (original build system)
    cmake_minimum_required(VERSION 3.13)
    project(lwm2m_protobuf C)

    # Concise CMake: expects pre-generated nanopb sources in include/

    set(GEN_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set(GEN_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
    set(GEN_SRC ${GEN_SRC_DIR}/lwm2m.pb.c)

    # Allow user to point to an existing nanopb checkout that provides pb.h
    set(NANOPB_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/build/nanopb-0.4.9.1 CACHE PATH "Path to nanopb root (contains pb.h)")
    option(LWM2M_WITH_NANOPB_RUNTIME "Compile nanopb runtime sources into this library" OFF)

    if(NOT EXISTS ${NANOPB_ROOT}/pb.h)
        message(FATAL_ERROR "pb.h not found in ${NANOPB_ROOT}. Run 'make nanopb' or set -DNANOPB_ROOT=/path/to/nanopb")
    endif()
    if(NOT EXISTS ${GEN_SRC})
        message(FATAL_ERROR "Missing generated source: ${GEN_SRC}. Run 'make generate' first.")
    endif()

    file(GLOB LWM2M_EXTRA_SRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

    add_library(lwm2m_protobuf STATIC ${GEN_SRC} ${LWM2M_EXTRA_SRC})

    if(LWM2M_WITH_NANOPB_RUNTIME)
        foreach(_f pb_common.c pb_encode.c pb_decode.c)
            if(EXISTS ${NANOPB_ROOT}/${_f})
                target_sources(lwm2m_protobuf PRIVATE ${NANOPB_ROOT}/${_f})
            else()
                message(FATAL_ERROR "Missing ${_f} in ${NANOPB_ROOT}. Disable LWM2M_WITH_NANOPB_RUNTIME or correct NANOPB_ROOT.")
            endif()
        endforeach()
    endif()

    target_include_directories(lwm2m_protobuf
        PUBLIC
            ${GEN_INC_DIR}
        PRIVATE
            ${NANOPB_ROOT}
    )

    if(MSVC)
        target_compile_options(lwm2m_protobuf PRIVATE /W4 /WX)
    else()
        target_compile_options(lwm2m_protobuf PRIVATE -Wall -Wextra -Werror)
    endif()

    set_target_properties(lwm2m_protobuf PROPERTIES C_STANDARD 99 POSITION_INDEPENDENT_CODE ON)

    option(LWM2M_INSTALL "Install library and headers" OFF)
    if(LWM2M_INSTALL)
        include(GNUInstallDirs)
        install(TARGETS lwm2m_protobuf ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
        set(_INSTALL_HEADERS ${GEN_INC_DIR}/lwm2m.pb.h ${GEN_INC_DIR}/lwm2m_helpers.h)
        if(LWM2M_WITH_NANOPB_RUNTIME)
            list(APPEND _INSTALL_HEADERS ${NANOPB_ROOT}/pb.h ${NANOPB_ROOT}/pb_common.h ${NANOPB_ROOT}/pb_encode.h ${NANOPB_ROOT}/pb_decode.h)
        endif()
        install(FILES ${_INSTALL_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lwm2m)
    endif()
endif()
