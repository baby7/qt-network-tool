import subprocess

current_version = "v1.0.0"
# 定义版本号
version = current_version.replace("v", "V")
no_v_version = current_version.replace("v", "").replace("V", "")

# 步骤3: 执行 Nuitka 2.7.12 编译命令
print("开始执行 Nuitka 编译命令")
nuitka_command = [
    "nuitka",

    "--mingw64",                                                            # 使用 MinGW64 编译器
    # "--standalone",                                                         # 生成一个包含所有依赖的文件夹，里面有可执行文件和依赖。
    "--onefile",                                                            # 生成一个可执行文件
    "--windows-console-mode=disable",                                       # 禁用控制台窗口

    "--enable-plugin=pyside6",                                              # 使用 PySide6 插件
    "--disable-plugin=pyqt5,pyqt6",                                         # 禁用 PyQt5 和 PyQt6 插件

    # "--windows-icon-from-ico=resources/img/icon/icon.ico",                  # 图标路径
    "--output-dir=out",                                                     # 输出目录

    "--lto=yes",                                                            # 启用 Link Time Optimization（LTO）以优化编译速度和性能。
    "--jobs=14",                                                            # 使用 16 个线程并行编译，加速编译速度。
    "--show-progress",                                                      # 显示编译进度。
    "--show-memory",                                                        # 显示内存使用情况。

    "PySide6NetworkTool.py"
]
process = subprocess.run(nuitka_command, check=True, shell=True)
print("完成 Nuitka 编译命令")

print("所有步骤已完成！")
