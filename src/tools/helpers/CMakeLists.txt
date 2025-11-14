
# Helper library
add_library(helpers STATIC
    IniFile.cpp
    StringHelpers.cpp
    Timer.cpp
    TimerPool.cpp
    WorkerThreadPool.cpp
)
target_include_directories(helpers PUBLIC .)
set_target_properties(helpers PROPERTIES OUTPUT_NAME "open-ocpp_static_helpers")
