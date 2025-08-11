cmake_minimum_required(VERSION 3.16)
project(PasswordManager VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6 components
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Gui)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Enable Qt MOC
set(CMAKE_AUTOMOC ON)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/main_window.cpp
    src/password_database.cpp
    src/password_entry.cpp
    src/crypto_utils.cpp
    src/logger.cpp
    src/settings.cpp
    src/settings_dialog.cpp
)

# Header files
set(HEADERS
    include/main_window.h
    include/password_database.h
    include/password_entry.h
    include/crypto_utils.h
    include/logger.h
    include/settings.h
    include/settings_dialog.h
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link Qt libraries
target_link_libraries(${PROJECT_NAME} 
    Qt6::Core 
    Qt6::Widgets 
    Qt6::Gui
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Set output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# Create data directory in build
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data)
