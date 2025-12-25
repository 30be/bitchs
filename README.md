# BitcHS

BitCoin implementation in Haskell

The project was written from scratch over the course of 4 days, taking almost 30 hours - that includes studying the theory behind it, and playing around with code.

You can generate a key pair, create, encode and sign a transaction, sending virtual money from one address to another.

Here is it: <https://mempool.space/testnet/tx/f0a55cba25df251951f952df935390ca91ad0f1d2e9f1af718a52f548dc373cc>

It was successfully tested on the bitcoin testnet, so it should work just the same on the main network as well.

## Resources

[Andrej Karpathy's blog post](https://karpathy.github.io/2021/06/21/blockchain/): it is the original inspiration for the project. I closely followed his article when writing the serialization and data structures.

[Elliptic Curve Cryptography: a gentle introduction by Andrea Corbellini](https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/): This blog post series was recommended by Andrej, so I closely followed it, writing the code for elliptic curves, RSA (even though it is not needed - I was interested)

[Wikipedia article on SHA](https://en.wikipedia.org/wiki/SHA-2#Pseudocode): While mostly bit scrambling, it was still interesting to implement.
