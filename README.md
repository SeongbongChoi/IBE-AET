# IBE-AET
This is the implementation of the paper, **Attack and improvement of the recent identity-based encryption with authorized equivalence test in cluster computing**, published at ([URL](https://link.springer.com/article/10.1007/s10586-021-03409-x)).

## Required Libraries
1. GMP library
2. PBC library
3. OpenSSL

## Build the Project
```bash
mkdir build
cd build
cmake ..
make
```

## Running the Code
- `-p`: PBC pairing parameter file
- `-n`: the number of iteration

Example usage:
```
./bin/frontend -p params/e256.param -n 10 
```
