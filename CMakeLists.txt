cmake_minimum_required( VERSION 3.27 )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_COMPILER riscv64-elf-g++ )

set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_COMPILER riscv64-elf-gcc )

add_compile_definitions( KAINE_OBF_KEY_HASH=0 )

include_directories( include )
include_directories( ../../../../include )
include_directories( ../../include )

file( GLOB SRC_FILES
    src/*.cc
)

add_library( VmEoP24-26229 ${SRC_FILES} )
