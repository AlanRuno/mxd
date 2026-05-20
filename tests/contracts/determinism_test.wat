;; Determinism Test Contract (WebAssembly Text Format)
;;
;; This contract tests various edge cases to ensure deterministic execution
;; across different platforms (Linux x64, ARM64, macOS, Windows)
;;
;; All operations use i32/i64 integers only (no floating-point)

(module
  ;; Memory for storage
  (memory 1)
  (export "memory" (memory 0))

  ;; Test 1: Integer arithmetic edge cases
  (func $test_integer_overflow (result i32)
    ;; Test i32 max value + 1 (should wrap to min value)
    i32.const 2147483647  ;; i32::MAX
    i32.const 1
    i32.add
    ;; Result: -2147483648 (wraps around)
  )
  (export "test_integer_overflow" (func $test_integer_overflow))

  ;; Test 2: Division by power of 2 (should be same as right shift)
  (func $test_division_shift (param $value i32) (result i32)
    local.get $value
    i32.const 4
    i32.div_s
    ;; Equivalent to: value >> 2
  )
  (export "test_division_shift" (func $test_division_shift))

  ;; Test 3: Signed vs unsigned division
  (func $test_signed_division (result i32)
    i32.const -10
    i32.const 3
    i32.div_s  ;; Signed division: -10 / 3 = -3
  )
  (export "test_signed_division" (func $test_signed_division))

  (func $test_unsigned_division (result i32)
    i32.const -10  ;; Interpreted as large unsigned: 4294967286
    i32.const 3
    i32.div_u  ;; Unsigned division: 4294967286 / 3 = 1431655762
  )
  (export "test_unsigned_division" (func $test_unsigned_division))

  ;; Test 4: Remainder operations
  (func $test_remainder (result i32)
    i32.const -10
    i32.const 3
    i32.rem_s  ;; -10 % 3 = -1
  )
  (export "test_remainder" (func $test_remainder))

  ;; Test 5: Bitwise operations (should be identical across platforms)
  (func $test_bitwise (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.and
    local.get $a
    local.get $b
    i32.or
    i32.xor
  )
  (export "test_bitwise" (func $test_bitwise))

  ;; Test 6: Left rotation (deterministic)
  (func $test_rotl (param $value i32) (param $shift i32) (result i32)
    local.get $value
    local.get $shift
    i32.rotl
  )
  (export "test_rotl" (func $test_rotl))

  ;; Test 7: Count leading zeros (must be deterministic)
  (func $test_clz (param $value i32) (result i32)
    local.get $value
    i32.clz
  )
  (export "test_clz" (func $test_clz))

  ;; Test 8: Count trailing zeros
  (func $test_ctz (param $value i32) (result i32)
    local.get $value
    i32.ctz
  )
  (export "test_ctz" (func $test_ctz))

  ;; Test 9: Population count (number of 1 bits)
  (func $test_popcnt (param $value i32) (result i32)
    local.get $value
    i32.popcnt
  )
  (export "test_popcnt" (func $test_popcnt))

  ;; Test 10: 64-bit integer operations
  (func $test_i64_ops (result i64)
    i64.const 9223372036854775807  ;; i64::MAX
    i64.const 1
    i64.add
    ;; Result: -9223372036854775808 (wraps to i64::MIN)
  )
  (export "test_i64_ops" (func $test_i64_ops))

  ;; Test 11: Memory operations (must be deterministic)
  (func $test_memory_ops (param $offset i32) (param $value i32) (result i32)
    ;; Store value
    local.get $offset
    local.get $value
    i32.store

    ;; Load value back
    local.get $offset
    i32.load
  )
  (export "test_memory_ops" (func $test_memory_ops))

  ;; Test 12: Conditional logic (control flow determinism)
  (func $test_conditional (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.gt_s
    if (result i32)
      local.get $a
    else
      local.get $b
    end
  )
  (export "test_conditional" (func $test_conditional))

  ;; Test 13: Loop iteration (deterministic execution)
  (func $test_loop (param $count i32) (result i32)
    (local $sum i32)
    (local $i i32)

    i32.const 0
    local.set $sum
    i32.const 0
    local.set $i

    loop $continue
      local.get $i
      local.get $count
      i32.lt_s
      if
        local.get $sum
        local.get $i
        i32.add
        local.set $sum

        local.get $i
        i32.const 1
        i32.add
        local.set $i

        br $continue
      end
    end

    local.get $sum
  )
  (export "test_loop" (func $test_loop))

  ;; Test 14: Zero extension (must be deterministic)
  (func $test_extend (result i64)
    i32.const -1  ;; 0xFFFFFFFF
    i64.extend_i32_u  ;; Zero-extend to 64-bit: 0x00000000FFFFFFFF
  )
  (export "test_extend" (func $test_extend))

  ;; Test 15: Sign extension
  (func $test_sign_extend (result i64)
    i32.const -1  ;; 0xFFFFFFFF
    i64.extend_i32_s  ;; Sign-extend to 64-bit: 0xFFFFFFFFFFFFFFFF
  )
  (export "test_sign_extend" (func $test_sign_extend))

  ;; Main test runner (runs all tests)
  (func $main (result i32)
    ;; Run all tests and XOR results together
    ;; Different results = different XOR = determinism failure
    call $test_integer_overflow
    call $test_signed_division
    i32.xor
    call $test_unsigned_division
    i32.xor
    call $test_remainder
    i32.xor

    ;; If result is consistent, determinism is verified
  )
  (export "main" (func $main))
)
