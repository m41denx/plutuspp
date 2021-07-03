# Plutus++
### Plutus++ is an automated bitcoin wallet collider that brute forces random wallet addresses 
Original concept (python): [Plutus](https://github.com/Isaacdelly/Plutus)

Optimized fork (python): [Plutus-Scroo](https://github.com/franzkruhm/Plutus-Scroo)

---
**This project is under heavy development. Do not use**

## What is Plutus++
Plutus++ is simply a rewrite of Plutus in pure C++ with intent of making a normal executable binary

KEYGEN STATE:
 - PRIVATE KEY      [OK]
 - PUBLIC KEY       [OK]
 - PUBLIC COMP KEY  [OK]
 - ADDRESS          [OK]
 - ADDRESS COMP     [OK]

 PERFORMANCE:
 - **Vanilla** 8K | **amd64 2 Thr** ➡ 1.6s | MEM: 90K
 - **Vanilla** 8K | **arm64 8 Thr** ➡ 0.8s | MEM: 100K
 - **Preload** 33M TXT | **amd64 2 Thr** ➡ 6.9s | MEM: 2.1G




 TODO:
 - [X] Use pointer as gen arg instead of copy
 - [ ] Remove limited addr count amount
 - [ ] Add Litecoin compatibility