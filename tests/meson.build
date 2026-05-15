# Tests for eggdrop C components
#
# Each test is a standalone executable that includes the necessary
# source files directly (unity build style).

# Include directories for tests
test_inc = [top_inc, src_inc, libop_inc]

# C arguments for tests
test_c_args = [
  '-std=gnu23',
  '-DMAKING_TESTS',
  '-DHAVE_CONFIG_H',
  '-DHANDLEN=@0@'.format(opt_handlen),
]

# Test executables
test_strbuf = executable('test_strbuf',
  'test_strbuf.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

test_rfc1459 = executable('test_rfc1459',
  'test_rfc1459.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

test_match = executable('test_match',
  'test_match.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

test_flags = executable('test_flags',
  'test_flags.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

test_botmsg = executable('test_botmsg',
  'test_botmsg.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

test_net = executable('test_net',
  'test_net.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

test_misc = executable('test_misc',
  'test_misc.c',
  include_directories: test_inc,
  c_args: test_c_args,
  dependencies: [libop_dep],
)

# Register tests with meson
test('strbuf', test_strbuf)
test('rfc1459', test_rfc1459)
test('match', test_match)
test('flags', test_flags)
test('botmsg', test_botmsg)
test('net', test_net)
test('misc', test_misc)
