{-# LANGUAGE OverloadedLists #-}
-- Credits to https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Main where

import Bitcoin (Script (Script), TxIn (..), TxOut (..), testIdentity)
import qualified Bitcoin as BTC
import qualified Data.ByteString as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import EC (Curve (..), Point (..), mkKeypair, mkKeypairFromString, scalarMultiply, signMessage, verifySignature)
import Numeric (showHex)
import qualified SHA256

testKeyExchange :: IO ()
testKeyExchange = do
  (alicePrivate, alicePublic) <- mkKeypair
  putStrLn $ "Alice's private key: " <> showHex alicePrivate ""
  putStrLn $ (const "Alice's public key: " <> (showHex @Integer) alicePublic.x <> const ", " <> showHex alicePublic.y) ""

  (bobPrivate, bobPublic) <- mkKeypair
  putStrLn $ "Bob's private key: " <> showHex bobPrivate ""
  putStrLn $ (const "Bob's public key: " <> showHex bobPublic.x <> const ", " <> showHex bobPublic.y) ""

  let secret1 = scalarMultiply alicePrivate bobPublic
  let secret2 = scalarMultiply bobPrivate alicePublic
  putStrLn $ if secret1 == secret2 then "Secrets match!" else "Mismatch: " <> show secret1 <> " vs " <> show secret2

testSHA :: IO ()
testSHA = do
  checkHash "" 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  checkHash "hello" 0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  where
    checkHash s desired = do
      let emptyStringHash = SHA256.bytesToInt $ B.unpack $ SHA256.hash s
      BC8.putStrLn $ if emptyStringHash == desired then "Successful hash!" else "Hash failed. See: " <> BC8.pack (showHex emptyStringHash "")

testSigning :: IO ()
testSigning = do
  (private, public) <- mkKeypair
  (falsePrivate, _) <- mkKeypair
  let message = "CGSG FOREVER"
  signature <- signMessage private message
  falseSignature1 <- signMessage private "Some other message"
  falseSignature2 <- signMessage falsePrivate message
  BC8.putStrLn $ "message: " <> message
  BC8.putStrLn $ "signature: " <> BC8.pack (show signature)
  putStrLn $ if verifySignature public message signature then "The true signature was succesfully verified" else "The signature was not verified"
  putStrLn $ if verifySignature public message falseSignature1 then "The false signature 1 was verified" else "The false signature 1 was not verified"
  putStrLn $ if verifySignature public message falseSignature2 then "The false signature 2 was verified" else "The false signature 2 was not verified"

testBlockChain :: IO ()
testBlockChain = do
  let alice = testIdentity "ALICE CGSG forever" -- address : n3yw3oygzfJ5sZxfKjDKeA4EqZKdqfEAHZ
      bob = testIdentity "BOB CGSG forever" -- address : mpoAqtJpdZbWoMEsr2Cod9fPNwpi9HHkWg
      -- https://mempool.space/testnet/tx/30cfb03e95b700b27dec4e42d172bc779eb85957d5b16f67da696a7588c07e64
      opDup = [118]
      opHash160 = [169]
      opEqualVerify = [136]
      opCheckSig = [172]
      txIdHash = SHA256.wordToByteString 20 (0x65ca433e32228302b9bc76c87d7e83742ae2f69d :: Integer) -- Serialized public key - it was computed by the faucet from the provided address
      bob_pkb_hash = BTC.encodePublicKey bob.public True True -- the same as txIdHash; it shows who is the owner of the cash now.
      alice_pkb_hash = BTC.encodePublicKey alice.public True True
      -- This is a transaction from a btc-testnet faucet to Bob (tx=transaction)
      txIn =
        BTC.TxIn
          { prevTx = SHA256.wordToByteString 32 (0x30cfb03e95b700b27dec4e42d172bc779eb85957d5b16f67da696a7588c07e64 :: Integer),
            prevIndex = 1, -- 0th index came to the sender back (they did not spend the entirety of their money)
            scriptSig = Script [opDup, opHash160, txIdHash, opEqualVerify, opCheckSig], -- Common pattern
            _sequence = 0xffffffff
          }
      txToAlice =
        TxOut
          { amount = 50000,
            scriptPubkey = Script [opDup, opHash160, alice_pkb_hash, opEqualVerify, opCheckSig] -- We are sending 50 000 satoshi to alice
          }

      txBack =
        TxOut
          { amount = 49000, -- Actually, just 136 sat was enough fee to transfer what we had, but I set a 1000 to be sure
            scriptPubkey = Script [opDup, opHash160, bob_pkb_hash, opEqualVerify, opCheckSig] -- We are sending 50 000 satoshi to alice
          }
  -- The rest goes to Bob back, with 2500 of them as fee

  -- At each transaction, we are spending the entirety of money received.
  putStrLn $ "Alice's " <> show alice
  putStrLn $ "Bob's " <> show bob
  putStrLn $ const "Bob's hash (should match with the faucet's one):" <> showHex (SHA256.bytesToInt $ BS.unpack bob_pkb_hash) $ ""
  return ()

main :: IO ()
main = do
  testBlockChain

-- testKeyExchange
-- testSHA
-- testSigning
