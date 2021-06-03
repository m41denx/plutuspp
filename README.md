# Plutus++
### Plutus++ is an automated bitcoin wallet collider that brute forces random wallet addresses 
Original: [Plutus](https://github.com/Isaacdelly/Plutus)
Optimized fork: [Plutus-Scroo](https://github.com/franzkruhm/Plutus-Scroo)

## What is Plutus++
Plutus++ is simply a rewrite of Plutus in pure c++ with inetent of making a normal executable binary

### Deps
Dependencies status marked as **[~~~]** and mean **Implemented**, **Tested**, **Merged to main script** with **X** - "not", **#** - "yes", **E** - "error found"

So `Feature [#EX]` means that feature is implemented and tested, however the test has failed and also it isn't merged


**DEPS**
- base58 [##X]
- ecdsa (SECP256k1) [##X]
  
```
priv -> OK
pub -> OK
pub_comp -> OK
W
```
- sha256 [##X]
- ripemd160 [##X]
- 