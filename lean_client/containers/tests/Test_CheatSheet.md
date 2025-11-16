### All tests
```bash
cargo test -p containers --test main
```

### Only test vectors
```bash
cargo test -p containers --test main test_vectors
```

### Only unit tests
```bash
cargo test -p containers --test main unit_tests
```

### Specific test category
```bash
cargo test -p containers --test main test_vectors::block_processing
cargo test -p containers --test main test_vectors::genesis
cargo test -p containers --test main unit_tests::state_process
```

### With output
```bash
cargo test -p containers --test main test_vectors -- --nocapture
```