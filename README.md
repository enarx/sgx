[![Workflow Status](https://github.com/enarx/sgx/workflows/test/badge.svg)](https://github.com/enarx/sgx/actions?query=workflow%3A%22test%22+branch%3Amain)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/sgx.svg)](https://isitmaintained.com/project/enarx/sgx "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/sgx.svg)](https://isitmaintained.com/project/enarx/sgx "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# sgx

This crate contains types for building an Intel SGX implementation.

Fully understanding the contents of this crate will likely require access
to the [Intel Software Developer Manual](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html).

How to use this crate partly depends on what you are trying to accomplish:

  1. If you are an enclave developer, you probably want the `parameters`
     and `ssa` modules.
  2. If you are signing an enclave, you probably want the `signature` and
     `crypto` modules.
  3. If you are developing an enclave loader, you probably want the
     `parameters` and `page` modules. However, you may also want the
     `signature` module to load a signature.

License: Apache-2.0
