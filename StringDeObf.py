import logging
import os
import sys
from unicorn import *
import struct
from androidemu.emulator import Emulator


# logging.basicConfig(  # 设置日志
#     stream=sys.stdout,
#     level=logging.DEBUG,
#     format='%(asctime)s %(levelname)7s %(name)34s | %(message)s'
# )
# logger = logging.getLogger(__name__)

str_datas = {}


def patch_str(origin_data: bytearray, data: bytes, start: int, size: int):
    origin_data[start: start + size] = data


def string_deobfuscate(filename: str):

    def hook_mem_write(uc, type, address, size, value, userdata):  # 当发生写内存操作时进行Hook
        try:
            curr_data = struct.pack("I", value)[:size]  # 转byte，截取前size大小
            global str_datas
            str_datas[address] = curr_data
        except:
            print(size)

    emulator = Emulator(vfp_inst_set=True, vfs_root='vfs')  # 创建模拟器
    emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)  # 添加Hook，需在加载so前
    lib_module = emulator.load_library(filename, do_init=True)  # 补充加载libc.so，不然可能会有问题
    base_addr = lib_module.base

    with open(filename, 'rb') as f:
        origin_data = bytearray(f.read())
        origin_len = len(origin_data)

    # 修复字符串
    global str_datas
    for address, value in str_datas.items():
        if base_addr < address < base_addr + lib_module.size:  # 判断是否是我们需要的so文件内存空间
            offset = address - base_addr - 0x1000  # 加载的基址还多了个0x1000(不太明白)
            patch_str(origin_data, value, offset, len(value))  # 将解密后的字符串写回

    assert len(origin_data) == origin_len, "Error: size of data changed!!!"

    recovery_filename = filename[:-3] + "_recovered.so"
    with open(recovery_filename, 'wb') as f:
        f.write(origin_data)

    print(f'Successful! The path of recovered file: {os.path.abspath(recovery_filename)}')


if __name__ == "__main__":
    filename = "../obfstring.so"
    string_deobfuscate(filename)
