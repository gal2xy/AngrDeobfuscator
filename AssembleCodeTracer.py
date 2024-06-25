import re

import angr
import am_graph
# 只要只指令中的操作数不是立即数或者全局变量


# 建立x86_64汇编指令的数据库
instruction_db = {
    'mov': {
        'has_variant': False, # 指令是否有多个版本
        '': {
            'operands': [2], #操作数个数
            'implicit_registers': [],# 指令执行依赖的寄存器(隐藏的寄存器)
            'changes_flags': [],#指令执行后改变的标志位
            'depends_on_flags': [],#指令执行依赖的标志位
            'dest_operands': [0],
            'src_operands': [1]
        }
    },
    'movsx': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': [],
        'dest_operands': [0],
        'src_operands': [1]
    },
    'cmov': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': [],
        'dest_operands': [0],
        'src_operands': [1]
    },
    'add': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF', 'CF', 'OF', 'AF'],
        'depends_on_flags': [],
        'dest_operands': [0],
        'src_operands': [1]
    },
    'sub': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF', 'CF', 'OF', 'AF'],
        'depends_on_flags': [],
        'dest_operands': [0],
        'src_operands': [1]
    },
    'cmp': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF', 'CF', 'OF', 'AF'],
        'depends_on_flags': [],
        'dest_operands': [],# 对于比较指令，这就没有源和目的之分！！！
        'src_operands': []
    },
    'jmp': {
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': []
    },
    'jne': { # jnz = jne
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': ['ZF']
    },
    'xlat': {
        'has_variant': False,
        'operands': [0],
        'implicit_registers': ['al', 'bx'],
        'changes_flags': [],
        'depends_on_flags': []
    },
    'setz': {# setz 等价于 sete
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': ['ZF']
    },
    'sete': {
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': ['ZF']
    },
    'setl': {
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': ['SF', 'ZF']
    },
    'push': {
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': []
    },
    'pop': {
        'has_variant': False,
        'operands': [1],
        'implicit_registers': [],
        'changes_flags': [],
        'depends_on_flags': []
    },
    'xor': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF'],
        'depends_on_flags': []
    },
    'and': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF'],
        'depends_on_flags': []
    },
    'or': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF'],
        'depends_on_flags': []
    },
    'imul': {
        'has_variant': True,
        # 接下来的key即为操作数的个数
        1:{
            'operands': [1],  # imul 操作数可以是1个、2个或3个，这里简化为1个
            'implicit_registers': ['eax'],
            'changes_flags': ['CF', 'OF'],  # imul 指令可能会改变进位标志和溢出标志
            'depends_on_flags': [],
            'dest_operands': ['eax'],
            'src_operands': [0]
        },
        2:{
            'operands': [2],  # imul 操作数可以是1个、2个或3个，这里简化为1个
            'implicit_registers': [],
            'changes_flags': ['CF', 'OF'],  # imul 指令可能会改变进位标志和溢出标志
            'depends_on_flags': [],
            'dest_operands': [0],
            'src_operands': [1]
        },
        3:{
            'operands': [3],  # imul 操作数可以是1个、2个或3个，这里简化为1个
            'implicit_registers': [],
            'changes_flags': ['CF', 'OF'],  # imul 指令可能会改变进位标志和溢出标志
            'depends_on_flags': [],
            'dest_operands': [0],
            'src_operands': [1, 2]
        },
    },
    'test': {
        'has_variant': False,
        'operands': [2],
        'implicit_registers': [],
        'changes_flags': ['ZF', 'SF', 'PF', 'AF'],
        'depends_on_flags': []
    }
    # 添加其他指令...
}

# 寄存器列表
register_db = {
    'RAX': ['RAX', 'EAX', 'AX', 'AL', 'AH'],
    'RBX': ['RBX', 'EBX', 'BX', 'BL', 'BH'],
    'RCX': ['RCX', 'ECX', 'CX', 'CL', 'CH'],
    'RDX': ['RDX', 'EDX', 'DX', 'DL', 'DH'],
    'RSI': ['RSI', 'ESI', 'SI', 'SIL'],
    'RDI': ['RDI', 'EDI', 'DI', 'DIL'],
    'RBP': ['RBP', 'EBP', 'BP', 'BPL'],# 感觉RBP、RSP、RIP用不着
    'RSP': ['RSP', 'ESP', 'SP', 'SPL'],
    'RIP': ['RIP'],
    'R8': ['R8', 'R8D', 'R8W', 'R8B'],
    'R9': ['R9', 'R9D', 'R9W', 'R9B'],
    'R10': ['R10', 'R10D', 'R10W', 'R10B'],
    'R11': ['R11', 'R11D', 'R11W', 'R11B'],
    'R12': ['R12', 'R12D', 'R12W', 'R12B'],
    'R13': ['R13', 'R13D', 'R13W', 'R13B'],
    'R14': ['R14', 'R14D', 'R14W', 'R14B'],
    'R15': ['R15', 'R15D', 'R15W', 'R15B'],
}



def parse_operand(operand):
    '''
    解析操作数的类型：寄存器、立即数、内存引用
    :param operand:
    :return:
    '''
    operand = operand.strip()

    # 判断是否为寄存器.后一个捕获r8~r15相关寄存器。
    if re.match(r'^[er]?[abcds][xlhpi]$', operand) or re.match(r'(r[89]|r1[0-5])[dwb]?', operand):
        return 'register'
    # 判断是否为内存操作数
    elif re.match(r'^\[.*\]$', operand):
        return 'memory'
    # 判断是否为立即数
    elif re.match(r'(?:0[xX])?[0-9A-Fa-f]+h?', operand):
        return 'immediate'
    else:
        return 'unknown'


def parse_instruction(instruction):
    # 去掉前后的空白字符
    instruction = instruction.strip()
    # 使用正则表达式分割指令和操作数
    tokens = re.split(r'\s+', instruction, maxsplit=1)

    operator = tokens[0]
    operands = tokens[1].split(',') if len(tokens) > 1 else []


    if operator not in instruction_db:
        print(f"Unknown instruction: {operator}")
        exit(-1)

    instr_info = instruction_db[operator]
    operand_count = instr_info['operands']

    if len(operands) not in operand_count:
        print(f"Incorrect number of operands for {operator}: expected {operand_count}, got {len(operands)}")
        exit(-1)

    operand_types = [parse_operand(op.strip()) for op in operands]

    return {
        'operator': operator,
        'operands': [op.strip() for op in operands],
        'operand_types': operand_types,
        'implicit_registers': instr_info['implicit_registers'],
        'changes_flags': instr_info['changes_flags'],
        'depends_on_flags': instr_info['depends_on_flags']
    }


def find_register(register):
    '''
    根据给定寄存器，查找对应的寄存器(最大)
    :param register:
    :return:
    '''
    for key, registers in register_db.items():
        if register in registers:
            return key

    return None


def ACT(filename, start_addr):
    project = angr.Project(filename, load_options={'auto_load_libs': False})
    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    target_func = cfg.functions.get(start_addr)
    supergraph = am_graph.to_supergraph(target_func.transition_graph)

    test_node_addr = 0x401302
    for node in supergraph.nodes():
        if node.addr == test_node_addr:
            block = project.factory.block(node.addr, node.size)
            start_insn = block.capstone.insns[-1]


            unknown_vars = set([])  # 存储指令中的未知变量，并利用这个跟踪来源
            nop_insns = [start_insn]  # 存储需要nop的指令的地址  start_insn.address, start_insn.size
            current_insn = start_insn
            current_insn_db = parse_instruction(start_insn.mnemonic + ' ' + start_insn.op_str)
            while True:
                operands = current_insn_db['operands']
                operand_types = current_insn_db['operand_types']
                for op, op_type in zip(operands, operand_types):
                    if op_type is 'register':


                        unknown_vars.add()
                    elif op_type is 'memory':

                    elif op_type is 'immediate':

                        unknown_vars
            # for insn in block.capstone.insns:
            #     parse_instruction(insn.mnemonic + ' ' + insn.op_str)


if __name__ == "__main__":
    filename = "../checkpassBogus"
    start_addr = 0x401130

    ACT(filename, start_addr)


