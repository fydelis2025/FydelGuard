cmake_minimum_required(VERSION 3.16)
project(FydelGuard VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt5 COMPONENTS Widgets REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CLAMAV REQUIRED libclamav)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# 🔥 SEM "src/" — arquivos na raiz
set(SOURCES
    main.cpp
    GuardView.cpp
    Scanner.cpp
    ScanWorker.cpp
    RealTimeMonitor.cpp
    QuarantineManager.cpp
    Updater.cpp
    FirewallManager.cpp
)

set(HEADERS
    GuardView.h
    Scanner.h
    ScanWorker.h
    RealTimeMonitor.h
    QuarantineManager.h
    Updater.h
    FirewallManager.h
)

add_executable(fydelguard ${SOURCES} ${HEADERS})

target_link_libraries(fydelguard PRIVATE
    Qt5::Widgets
    ${CLAMAV_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    pthread
    stdc++fs
)

target_include_directories(fydelguard PRIVATE
    ${CLAMAV_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

install(TARGETS fydelguard RUNTIME DESTINATION /usr/local/bin)
