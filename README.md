This is an implementation for SUMAC. It relies on `openmls`, an implementation of the MLS protocol.


# Rust installation

To install rust and its project manager cargo, go to https://www.rust-lang.org/tools/install



## Running the benchmarks

The benchmarks use the `criterion` framework and must be run in the `sumac_rs` directory. The commands 

```
cd sumac_rs
cargo bench
```

will run all the benchmarks for SUMAC (functions `add-user` and `add-admin`) and for the simple CGKA (`add-user`).



**Disclaimer**: This software is a prototype implementation. Do not use it in production environments.

