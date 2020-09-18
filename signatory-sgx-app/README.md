# signatory-sgx-app [![crate][crate-image]][crate-link] [![Docs][docs-image]][docs-link] [![Build Status][build-image]][build-link] ![MIT/Apache2 licensed][license-image]

Tendermint Validator app in SGX environment.
It should be compiled in a reproducible build environment to the `x86_64-fortanix-unknown-sgx` target;
the binary should be converted to [the SGX stream format](https://edp.fortanix.com/docs/tasks/deployment/)
and signed according to the target platform (v1 vs v2 with a Flexible Launch Control).

## License

**Signatory** is distributed under the terms of either the MIT license or the
Apache License (Version 2.0), at your option.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.