import os

import angr

import am_graph
from collections import defaultdict

def fill_nop(origin_data: bytearray, start: int, size: int):
    # 0x90 is hardcode of nop
    origin_data[start: start + size] = (0x90).to_bytes(1, "big") * size


def patch_jmp(origin_data: bytearray, jmp_insn_offset: int, target_offset: int):

    # The length of jmp instruction
    jmp_insn_len = 5

    # 0xE9 is hardcode of near jmp, which use 32bits Operand as offset
    opcode = (0xE9).to_bytes(1, "big")

    # Caculate the Operand of jmp instruction
    # If offset is negative, we need to use two's complement
    # Offset should use little endian to storage
    jmp_offset = target_offset - (jmp_insn_offset + jmp_insn_len)
    if jmp_offset < 0:
        jmp_offset = (1 << 32) + jmp_offset
    jmp_offset = jmp_offset.to_bytes(4, "little")

    # Patch the corresponding position with jmp instruction
    origin_data[jmp_insn_offset: jmp_insn_offset + jmp_insn_len] = opcode + jmp_offset


repeate_count = defaultdict(int)
def debcf(filename: str, start_addr: int):

    def filter_condition(state):
        if state.addr in reachable_blocks:
            repeate_count[state.addr] += 1
        if repeate_count[state.addr] > 50:
            return True
        else:
            return False


    project = angr.Project(filename, load_options={'auto_load_libs': False})
    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    target_func = cfg.functions.get(start_addr)
    supergraph = am_graph.to_supergraph(target_func.transition_graph)

    # 模拟执行整个函数,记录执行到的块，没有执行到的块视为虚假块，后续可nop掉，然后修复虚假块的前继块
    print('*******************symbolic execution*********************')
    inital_state = project.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES})
    simgr = project.factory.simgr(inital_state)

    reachable_blocks = set([])
    while len(simgr.active) > 0:
        # simgr.drop(stash='active', filter_func=filter_condition)
        for active_state in simgr.active:
            reachable_blocks.add(active_state.addr)
        simgr.step()

    print(f'executed block: {[hex(addr) for addr in reachable_blocks]}')
    # print(f'executed cnt: {[(hex(addr), count) for addr, count in repeate_count.items()]}')


    print('************************patch******************************')
    with open(filename, "rb") as f:
        origin_data = bytearray(f.read())
        origin_len = len(origin_data)

    recovery_filename = filename + "_recovered"
    recovery_file = open(recovery_filename, "wb")


    for node in supergraph.nodes():
        #对未执行的块(虚假块)进行nop
        if node.addr not in reachable_blocks:
            offset = node.addr - base_addr
            fill_nop(origin_data, offset, node.size)
        else:
            # 对已执行的块查找其后继块是否存在虚假块，如果存在则修改条件跳转为jmp指令
            succ_nodes = list(supergraph.successors(node))
            jmp_targets = []
            for succ_node in succ_nodes:
                if succ_node.addr in reachable_blocks:
                    jmp_targets.append(succ_node.addr)

            # 存在后继块为虚假块，修改条件跳转指令为jmp指令
            if len(succ_nodes) > 1 and len(jmp_targets) == 1:
                block = project.factory.block(node.addr, node.size)
                # 一般认为最后一条指令为条件跳转指令
                last_insn = block.capstone.insns[-1]
                patch_jmp(origin_data, last_insn.address - base_addr, jmp_targets[0] - base_addr)
            # 对于多余的指令，怎么进行nop优化
    assert len(origin_data) == origin_len, "Error: size of data changed!!!"
    recovery_file.write(origin_data)
    recovery_file.close()
    print(f'Successful! The path of recovered file: {os.path.abspath(recovery_filename)}')


if __name__ == "__main__":

    filename = "../checkpassBogus2"
    start_addr = 0x401130

    debcf(filename, start_addr)