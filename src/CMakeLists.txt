file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/src/*.c ${CMAKE_SOURCE_DIR}/src/*.cpp )
include_directories(${CMAKE_SOURCE_DIR}/src/)

# OpenSSL
find_package(OpenSSL REQUIRED)

# GMP
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_path(GMPXX_INCLUDE_DIR NAMES gmpxx.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

# NTL
find_path(NTL_INCLUDE_DIR NAMES NTL)
find_library(NTL_LIBRARIES NAMES ntl libntl)

# OpenMP
find_package(OpenMP REQUIRED)

ADD_EXECUTABLE(main ${SRC_FRONTEND})

target_include_directories(main
    PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(DEP_LIBS
    OpenMP::OpenMP_CXX OpenSSL::Crypto OpenSSL::SSL ntl gmp gmpxx
)

target_link_libraries(main
    PUBLIC
    ${DEP_LIBS}
    -pthread
)

