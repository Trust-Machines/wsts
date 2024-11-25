# Usage

Applications which use `WSTS` will typically run both `Signer` and `Coordinator` state machines. To ensure flexibility, these state machines require the user to provide a random number generator (RNG) that implements the `RngCore` and `CryptoRng` traits.

### Providing an RNG

You can use the following RNG implementations:

- **Operating System RNG (`OsRng`)**
  
  ```rust
  use rand_core::OsRng;

  let mut rng = OsRng;
  ```

- **ChaCha20 RNG**
  
  ```rust
  use rand_chacha::ChaCha20Rng;

  let mut rng = ChaCha20Rng::from_entropy();
  ```

- **Custom RNGs**

  Implement your own RNG by adhering to the `RngCore` and `CryptoRng` traits.

### Example Usage

```rust
use rand_core::OsRng;
use wsts::v1::Signer;

// Initialize your RNG
let mut rng = OsRng;

// Create a signer
let signer = Signer::new(id, key_ids, N, T, &mut rng);
```

Ensure that you pass the RNG to all functions that require randomness.

This addresses the audit critical issues [CR-01](https://github.com/Trust-Machines/wsts/issues/66) and [CR-02](https://github.com/Trust-Machines/wsts/issues/67).