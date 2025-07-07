cmake_minimum_required(VERSION 3.10)

project(apps LANGUAGES C)

# 设置KP_DIR
if(NOT DEFINED KP_DIR)
    set(KP_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# 设置全局编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")

# 设置全局包含目录
set(KERNEL_INCLUDE_DIRS
        .
        include
        patch/include
        linux/include
        linux/arch/arm64/include
        linux/tools/arch/arm64/include
)

# 创建全局包含目录列表
set(GLOBAL_INCLUDE_DIRS "")
foreach(dir ${KERNEL_INCLUDE_DIRS})
    list(APPEND GLOBAL_INCLUDE_DIRS "${KP_DIR}/kernel/${dir}")
endforeach()

# 定义通用的KPM模块构建函数
function(add_kpm_module MODULE_NAME SOURCE_FILE)
    # 解析可选参数
    set(options "")
    set(oneValueArgs LINKER_SCRIPT)
    set(multiValueArgs "")
    cmake_parse_arguments(KPM "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # 创建目标文件
    add_library(${MODULE_NAME}_obj OBJECT ${SOURCE_FILE})

    # 设置包含目录
    target_include_directories(${MODULE_NAME}_obj PRIVATE ${GLOBAL_INCLUDE_DIRS})

    # 设置编译选项
    target_compile_options(${MODULE_NAME}_obj PRIVATE -O2 -fno-stack-protector -fno-builtin -nostdinc -fno-PIC -T${KP_DIR}/hello.lds})


    add_custom_target(${MODULE_NAME}.kpm ALL
            COMMAND ${CMAKE_C_COMPILER} -r -o ${MODULE_NAME}.kpm $<TARGET_OBJECTS:${MODULE_NAME}_obj>
            DEPENDS ${MODULE_NAME}_obj
            COMMENT "Generating ${MODULE_NAME}.kpm"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    # 添加清理规则
    add_custom_target(clean-${MODULE_NAME}
            COMMAND ${CMAKE_COMMAND} -E remove -f ${MODULE_NAME}.kpm
            COMMAND ${CMAKE_COMMAND} -E remove -f *.o
            COMMENT "Cleaning ${MODULE_NAME} files"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    # 将清理目标添加到全局清理依赖
    if(NOT TARGET clean-all-demos)
        add_custom_target(clean-all-demos
                COMMENT "Cleaning all demo files"
        )
    endif()
    add_dependencies(clean-all-demos clean-${MODULE_NAME})
endfunction()

# 添加demo子目录
# 包含modules目录下的所有子目录作为子项目
file(GLOB CHILD_MODULES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/kpms ${CMAKE_CURRENT_SOURCE_DIR}/kpms/*)
foreach(child ${CHILD_MODULES})
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/kpms/${child}")
        add_subdirectory(kpms/${child})
    endif()
endforeach()




