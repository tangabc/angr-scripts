"""
Full writeup of the walkthrough:
http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html
"""

import angr
import simuvex


# Globals
LEN_PW = 0x22
ADDR_PW_ORI = ADDR_HASH = 0
GOAL_HASH = 'UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW=='


def hook_heapalloc(state):
    state.regs.eax = ADDR_HASH


def main():
    global ADDR_PW_ORI, ADDR_HASH
    
    # Load binary
    p = angr.Project('sender')
    
    # Start with a blank state at the EIP after "key.txt" is read
    state = p.factory.blank_state(addr=0x401198, 
                                  remove_options={simuvex.o.LAZY_SOLVES})
    
    # Initialize global variables
    ADDR_PW_ORI = state.regs.ebp - 0x80004
    ADDR_HASH = state.regs.ebp - 0x40000
    
    # Setup stack to simulate the state after which the "key.txt" is read
    state.regs.esi = LEN_PW
    
    # Restrict the password to printable bytes, ending with a null byte
    pw_char = state.BV('PW_CHAR', 8)
    pw_str = pw_char
    for i in xrange(LEN_PW):
        state.add_constraints(pw_char >= 0x21, pw_char <= 0x7e)
        state.mem[ADDR_PW_ORI+i:].byte = pw_char
        pw_char = state.BV('PW_CHAR', 8)
        pw_str = pw_str.concat(pw_char)
        
    state.add_constraints(pw_char == 0)
    
    # To avoid calling imports (HeapAlloc), retrofit part of the stack as 
    # temporary buffer to hold symbolic copy of the password
    p.hook(0x4011D6, hook_heapalloc, length=5)
    
    # Explore the paths until after the hash is computed
    paths = p.factory.path_group(state, immutable=False)
    paths.explore(find=0x4011EC)
    
    # Add constraint to make final hash equal to the one we want
    # Also restrict the hash to only printable bytes
    found_s = paths.found[0].state
    for i in xrange(len(GOAL_HASH)):
        char = found_s.memory.load(ADDR_HASH + i, 1)
        found_s.add_constraints(char >= 0x21,
                                char <= 0x7e,
                                char == ord(GOAL_HASH[i]))
    
    # Solve for password that will result in the required hash
    print found_s.se.any_str(pw_str)


if __name__ == '__main__':
    main()