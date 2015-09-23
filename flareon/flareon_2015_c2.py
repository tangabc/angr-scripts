"""
Full writeup of the walkthrough:
http://0x0atang.github.io/reversing/2015/09/17/flareon2-concolic.html
"""

import angr, simuvex

# Load binary
p = angr.Project('very_success')

# Start with a blank state at the function sub_401084
initial_state = p.factory.blank_state(addr=0x401084, 
                                      remove_options={simuvex.o.LAZY_SOLVES})

# Populate stack to simulate calling function with required args
initial_state.stack_push(0x25)                  # arg_8__len_password
initial_state.stack_push(0x402159)              # arg_4__user_password
initial_state.stack_push(0x4010e4)              # arg_0__ref_key
initial_state.stack_push(0x401064)              # return addr

# Set the user input password as a symbolic buffer of bytes
PW_LEN = 0x25
initial_state.mem[0x402159:] = initial_state.BV('password', 8 * PW_LEN)

# Assume that the password consists of only printable bytes
for i in xrange(PW_LEN):
    char = initial_state.memory.load(0x402159 + i, 1)
    initial_state.add_constraints(char >= 0x21, char <= 0x7e)

# Create an execution path with our initial state
initial_path = p.factory.path(state=initial_state)

# Perform the path exploration using concolic execution
ex = angr.surveyors.Explorer(p, start=initial_path, find=(0x40106b,), 
                             avoid=(0x401072,), enable_veritesting=True)
concolic_run = ex.run()

# Extract the password that got us to the desired execution path
final_state = concolic_run.found[0].state
print final_state.se.any_str(final_state.memory.load(0x402159, PW_LEN))
