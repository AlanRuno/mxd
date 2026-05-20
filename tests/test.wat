(module
  (func $main (param i32) (result i32)
    local.get 0
    i32.const 42
    i32.add)
  (export "main" (func $main)))
