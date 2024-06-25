import opcode
import os
from typing import List

import angr
import capstone
import claripy
import pyvex
import am_graph
from collections import defaultdict
import argparse
from networkx.classes.digraph import DiGraph
from angr.knowledge_plugins.functions.function import Function


# Hardcode of conditional jump instructions in x86_64 architecture
x86_64_jmp_dict = {
    'ja': 0x0f87, 'jae': 0x0f83, 'jb': 0x0f82, 'jbe': 0x0f86, 'jc': 0x0f82, 'je': 0x0f84,
    'jz': 0x0f84, 'jg': 0x0f8f, 'jge': 0x0f8d, 'jl': 0x0f8c, 'jle': 0x0f8e, 'jna': 0x0f86,
    'jnae': 0x0f82, 'jnb': 0x0f83, 'jnbe': 0x0f87, 'jnc': 0x0f83, 'jne': 0x0f85, 'jng': 0x0f8e,
    'jnge': 0x0f8c, 'jnl': 0x0f8d, 'jnle': 0x0f8f, 'jno': 0x0f81, 'jnp': 0x0f8b, 'jns': 0x0f89,
    'jnz': 0x0f85, 'jo': 0x0f80, 'jp': 0x0f8a, 'jpe': 0x0f8a, 'jpo': 0x0f8b, 'js': 0x0f88
    }


def fill_nop(origin_data: bytearray, start: int, size: int):
    """
    The function is to use nop to fill the size space starting from start,
    where start is the file offset
    :param origin_data: The binary data of the program
    :param start: File offset that nop padding start in binary program
    :param size: The size of the nop padding
    :return:
    """
    # 0x90 is hardcode of nop
    origin_data[start: start + size] = (0x90).to_bytes(1, "big") * size


def patch_jmp(origin_data: bytearray, jmp_insn_offset: int, target_offset: int):
    """
     The function is to fill in a jmp instruction starting from jmp_insn_offset
    :param origin_data: The binary data of the program
    :param jmp_insn_offset: File offset that jump instruction in the binary program
    :param target_offset: File offset that jump target in the binary program
    :return:
    """
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


def patch_cmov(origin_data: bytearray, cmov_mne: str, cmov_insn_offset: int, target_offset: int):
    """
    The function is to replace `cmov` instructions with conditional jump instructions.
    :param origin_data: The binary data of the program
    :param cmov_mne: The mnemonic of cmov instruction
    :param cmov_insn_offset: File offset that cmov instruction in the binary program
    :param target_offset: File offset that conditional jump target in the binary program
    :return:
    """
    # The length of conditional jmp instruction
    jmp_insn_len = 6

    # Get the jmp mnemonic to the cmov mnemonic.
    # Lookup the opcode corresponding to the mnemonic using the dictionary.
    # And the opcode should storage in big endian
    jmp_mne = 'j' + cmov_mne[4:]
    jmp_opcode = x86_64_jmp_dict[jmp_mne]
    jmp_opcode = jmp_opcode.to_bytes(2, "big")

    # Caculate the Operand of jmp instruction
    # If offset is negative, we need to use two's complement
    # Offset should use little endian to storage
    jmp_offset = target_offset - (cmov_insn_offset + jmp_insn_len)
    if jmp_offset < 0:
        jmp_offset = (1 << 32) + jmp_offset
    jmp_offset = jmp_offset.to_bytes(4, "little")

    # Patch the corresponding position with jmp instruction
    origin_data[cmov_insn_offset: cmov_insn_offset + jmp_insn_len] = jmp_opcode + jmp_offset


def symbolic_execution(project: angr.Project, relevant_block_addrs: List[int], start_addr: int, modify_value: claripy.BV=None, inspect: bool=False):
    """
    The function's purpose is to use symbolic execution to
    find the jump relationships between relevant blocks.
    :param project: The angr project of binary program.
    :param relevant_block_addrs: The address list of relevant blocks, including prologue block and retn block, is used to determine which relevant blocks are the successor basic blocks of the current symbolic execution basic block.
    :param start_addr: Start address of symbolic execution.
    :param modify_value: modify_value is used to assign a value to a temporary variable in an ITE (if-then-else) expression condition. If the current relevant block has cmov instruction(i.e. it has two successor basic blocks), we should set modify_value to 0 and 1 so that symbolic execution can explore both branches.
    :param inspect: If the current relevant block has cmov instruction(i.e. it has two successor basic blocks), set inspect to True, otherwise to False
    :return: If symbolic execution finds the successor of the current relevant block, return the address of the successor. otherwise, return None.
    """

    def statement_inspect(state):
        """
        Modify the value of the temporary variable of the ITE (If-then-else) expression condition
        to modify_value, so that symbolic execution can execute the specified branch
        :param state: The binary program's simstate
        :return:
        """
        # Checks the expressions of the currently executing statement. if the expression is
        # pyvex.expr.ITE(i.e.if - else -then), modifies the value of the conditional temporary
        # variable of the expression. And clear all breakpoints associated with the state
        expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    def found_condition(state: angr.sim_state.SimState):
        """
        Expected conditions for simgr.explore()
        :param state: The binary program's simstate
        :return: Boolean
        """
        if state.addr != start_addr and state.addr in relevant_block_addrs:
            return True
        else:
            return False

    # Create state at start_addr and use it as the starting state for symbolic execution
    inital_state = project.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES})

    # If the current relevant block has two successors (i.e. ispect is True), we should set a breakpoint
    # This breakpoint will be triggered before each statement(语句) is executed, calling the processing function "statement_inspect"
    if inspect:
        inital_state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)

    # Create a simgr to explore successors of the current revelant block.
    # We judge by address, If the address of any active state is a member of the address set of relevant blocks (except the current relevant block itself), we consider that the successor relevant block of the current relevant block has been found, and return the address.
    simgr = project.factory.simgr(inital_state)
    simgr.explore(find=found_condition)
    if simgr.found:
        solution_state = simgr.found[0]
        return solution_state.addr

    return None


# 好像不行
def has_control_flow_flattening(function_cfg: Function):

    if function_cfg is None:
        return False

    block_count = len(list(function_cfg.blocks))
    supergraph = am_graph.to_supergraph(function_cfg.transition_graph)
    edge_count = len(supergraph.edges)
    jump_count = 0
    for block in function_cfg.blocks:
        for insn in block.capstone.insns:
            if insn.group(capstone.CS_GRP_JUMP):
                jump_count += 1

    print(f'jump_count = {jump_count}')
    print(f'block_count = {block_count}')
    print(f'edge_count = {edge_count}')

    # 如果跳转指令数量异常高，可能是控制流平坦化
    return



def deflat(filename: str, start_addr: int):

    def retn_procedure(state):
        """
        When encountering a call instruction, Use hooks to return directly so that
        symbolic execution does not go deep into other functions
        :param state: The binary program's simstate
        :return:
        """
        # 这是要干什么，不太明白
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)
        return

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    target_func = cfg.functions.get(start_addr)

    #has_control_flow_flattening(target_func)

    # a NetworkX DiGraph describing control flow within the function itself.
    # It resembles the control-flow graphs IDA displays on a per-function level.
    supergraph = am_graph.to_supergraph(target_func.transition_graph)


    # find the prologue block and the retn block. Simply assume that the block
    # whose successor block is 0 is the return block, and whose predecessor
    # block is 0 is the prologue
    prologue_node = None
    retn_node = None
    for node in supergraph.nodes():
        if supergraph.in_degree(node) == 0:# predecessors num
            prologue_node = node
        elif supergraph.out_degree(node) == 0:# successors num
            retn_node = node

    if prologue_node is None or retn_node is None:
        print("[*] error! can not find the prologue block or retn block!")
        exit(0)

    # find relevant blocks
    # 利用模式匹配寻找相关块，以下特征仅针对ollvm
    # 分发器中均存在从一个地方取数据，然后与固定值相减，最后跳转
    # 序言块和相关块都存在将数据存储在同一个地方
    # 预处理器的前继节点很多，且都是相关块，且跳转到住主分发器 √
    # 存在cmov指令的相关块至少两个后继节点


    # find the main dispatcher block and the predisaptcher block.
    # Simply think that the only successor node of the prologue block is main disaptcher block
    # Simply think that the two predecessor blocks of the main distributor block
    # are the prologue block and the predisaptcher
    main_dispatcher_node = list(supergraph.successors(prologue_node))[0]
    main_disaptcher_predecessors = list(supergraph.predecessors(main_dispatcher_node))
    pre_dispatcher_node = None
    if len(main_disaptcher_predecessors) == 2:
        if main_disaptcher_predecessors[0].addr == prologue_node.addr:
            pre_dispatcher_node = main_disaptcher_predecessors[1]
        else:
            pre_dispatcher_node = main_disaptcher_predecessors[0]
    else:
        print("Unable to handle the situation where the main distributor block has more than 2 predecessor blocks")
        exit(0)

    # 先初步认为预处理器的前继基本块为相关基本块 (会存在仅含jmp指令的假块)
    # relevant_nodes = list(supergraph.predecessors(pre_dispatcher_node))
    #
    # verify_by_insns = []
    # for node in relevant_nodes:
    #     block = project.factory.block(node.addr, node.size)
    #     print(block.capstone)
    #     print()
        # verify_by_insns.append((node, block.capstone.insns[-2]))

    relevant_nodes = []
    nop_nodes = []
    for node in supergraph.nodes():
        if supergraph.has_edge(node, pre_dispatcher_node) and node.size > 10:# 相关块
            relevant_nodes.append(node)
            continue
        if node.addr in (prologue_node.addr, retn_node.addr):# 序言块、返回块
            continue
        nop_nodes.append(node)

    relevant_block_addrs = [node.addr for node in relevant_nodes]

    print('*******************relevant blocks************************')
    print(f'prologue block: {hex(prologue_node.addr)}')
    print(f'main dispatcher block: {hex(main_dispatcher_node.addr)}')
    print(f'predispatcher block: {hex(pre_dispatcher_node.addr)}')
    print(f'retn block: {hex(retn_node.addr)}')
    print(f'relevant blocks: {[hex(addr) for addr in relevant_block_addrs]}', )


    # testing

    # def find_insn_relations(block):
    #     relation_dict = []
    #     inverse_insns = block.capstone.insns[::-1]
    #     print(f'inverse:')
    #     for insns in inverse_insns:
    #         print(insns, f'mnemonic = {insns.mnemonic}, op_str = {insns.op_str}')
    #     print()
    # for node in relevant_nodes:
    #     block = project.factory.block(node.addr, node.size)
    #     print(block.capstone)
    #     find_insn_relations(block)
    #
    # exit()


    '''
    找到相关块之间的执行顺序，angr符号执行，
    符号执行从每个真实块的起始地址开始，直到执行到下一个真实块
    如果遇到分支，就改变判断值执行两次来获取分支的地址，这里用angr的inspect在遇到类型为ITE的IR表达式时，改变临时变量的值来实现
    '''
    print('*******************symbolic execution*********************')
    relevants = relevant_nodes
    relevants.append(prologue_node)
    relevants_without_retn = list(relevants)
    relevant_block_addrs.extend([prologue_node.addr, retn_node.addr])# 所有真实块的地址

    flow = defaultdict(list)# 创建字典
    patch_insns = {}# 真实块中待修补的指令

    # 恢复真实块之间的跳转关系
    for node in relevants_without_retn:
        print(f'*******************dse {hex(node.addr)}*******************')
        block = project.factory.block(node.addr, node.size)
        has_braches = False
        hook_addrs = set()

        for cmov_insn in block.capstone.insns:
            if cmov_insn.mnemonic.startswith("cmov"):#有分支, 一个基本块中有没有可能有多个cmov指令？
                patch_insns[node] = cmov_insn
                has_braches = True
            elif cmov_insn.mnemonic.startswith("call"):
                hook_addrs.add(cmov_insn.address)

        # If the current relevant block has call instruction, use hook to replace it with return
        # 限制符号执行在当前函数范围内！
        if len(hook_addrs) == 0:
            # The length of call instruction
            skip_length = 5
            for hook_addr in hook_addrs:
                project.hook(addr=hook_addr, hook=retn_procedure, length=skip_length)

        if has_braches:
            target_addr1 = symbolic_execution(project, relevant_block_addrs, node.addr, claripy.BVV(1, 1), True)
            target_addr2 = symbolic_execution(project, relevant_block_addrs, node.addr, claripy.BVV(0, 1), True)
            if target_addr1 is not None:
                flow[node].append(target_addr1)
            if target_addr2 is not None:
                flow[node].append(target_addr2)
        else:
            target_addr = symbolic_execution(project, relevant_block_addrs, node.addr)
            if target_addr:
                flow[node].append(target_addr)

    print("************************relevant blocks' flow************************")
    for parent, child_addrs in flow.items():
        print(f'{hex(parent.addr)}: {[hex(child_addr) for child_addr in child_addrs]}')
    print(f'{hex(retn_node.addr)}: []')



    # 去混淆
    print('************************patch*****************************')
    with open(filename, "rb") as f:
        origin_data = bytearray(f.read())
        origin_len = len(origin_data)

    recovery_filename = filename + "_recovered"
    recovery_file = open(recovery_filename, "wb")

    for nop_node in nop_nodes:
        fill_nop(origin_data, nop_node.addr - base_addr, nop_node.size)

    # 修正真实块之间的跳转
    for parent, child_addrs in flow.items():
        # 对于只有一个后继块的，修改块中最后一条指令为jmp指令
        if len(child_addrs) == 1:
            parent_block = project.factory.block(parent.addr, parent.size)
            last_insn = parent_block.capstone.insns[-1]
            fill_nop(origin_data, last_insn.address - base_addr, last_insn.size)
            patch_jmp(origin_data, last_insn.address - base_addr, child_addrs[0] - base_addr)
        # 对于存在两个后继块的，修改块中的cmov指令为对应的jcc指令，然后在后面添加jmp指令跳转到另一个分支
        elif len(child_addrs) == 2:
            cmov_insn = patch_insns[parent]
            # patch from cmov to end
            fill_nop(origin_data, cmov_insn.address - base_addr, parent.size - (cmov_insn.address - parent.addr))
            # 替换成jcc指令 6字节  (True branch)
            patch_cmov(origin_data, cmov_insn.mnemonic, cmov_insn.address - base_addr, child_addrs[0] - base_addr)
            # jmp跳转 (False branch)
            patch_jmp(origin_data, cmov_insn.address + 6 - base_addr, child_addrs[1] - base_addr)
        # 所以>2个的后续块的呢？
        # 对于多余的指令，怎么进行nop优化? 跟踪cmov操作数，找到相关指令（能够让目的寄存器改变值的指令都进行深入跟踪），进行nop，不过汇编指令类型有点多，导致代码量大
    assert len(origin_data) == origin_len, "Error: size of data changed!!!"
    recovery_file.write(origin_data)
    recovery_file.close()
    print(f'Successful! The path of recovered file: {os.path.abspath(recovery_filename)}')


if __name__ == "__main__":
    filename = "../checkpassFlaten"
    start_addr = 0x401130
    deflat(filename, start_addr)