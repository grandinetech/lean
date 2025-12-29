### To select which devnet you want to compile

#### Option A
- Change the default features in root `Cargo.toml`:
```toml
[features]
default = ["devnet1", "<...other features>"]  # Change to "devnet2" if needed
devnet1 = [...]
devnet2 = [...]
```

#### Option B
- Use the `--no-default-features` flag and specify the desired devnet feature when building or running the project:
```bash
cargo build --no-default-features --features devnet1  # Change to devnet2
```


### Running tests for a specific devnet

From root directory, use the following command:
```bash
cargo test -p <crate_name> --no-default-features --features devnet1  # Change to devnet2
```

Use `<crate_name>` to specify the crate you want to test.