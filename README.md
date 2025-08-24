This is an implementation for SUMAC. It relies on `openmls`, an implementation of the MLS protocol. We extended this library with the module `tree_sumac`, which generaically handles all the low-level tree operations of SUMAC. The high-level API of SUMAC can be found in `sumac_rs`


# Rust installation

To install rust and its project manager cargo, go to https://www.rust-lang.org/tools/install and follow the instructions. 


## Running the benchmarks

All the benchmarks are reproducible by running a single command. The benchmarks use the `criterion` framework and must be run in the `sumac_rs` directory. The commands 

```
cd sumac_rs
cargo bench
```

will run all the benchmarks for SUMAC (functions `add-user` and `add-admin`) and for the simple CGKA (`add-user`).

The results will be displayed in JSIN format under `target/criterion` folder. To get human-readable format, you can run the `export_latex.py` script to produce the LateX tables of the paper.

Depending on your setup, benches can take a while to run. Every operation is run a hundred times (including a setup phase of construction of a random group), with the positions of committers and target of each operation randomized.


**Disclaimer**: This software is a prototype implementation. Do not use it in production environments.

