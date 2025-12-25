-- https://en.wikipedia.org/wiki/SHA-2
{-# LANGUAGE BinaryLiterals #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module SHA256 where

import Data.Bits (Bits, complement, rotateR, shiftR, xor, (.&.), (.<<.), (.>>.), (.|.))
import qualified Data.ByteString as B
import Data.Word (Word32, Word64, Word8)

-- 32-bit hash initial values
initialHash :: [Word32]
initialHash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

k :: [Word32]
k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

-- Big-endian conversion (standard for SHA-512)
wordToByteString :: (Integral a, Bits a) => Int -> a -> B.ByteString
wordToByteString bytes n = B.pack $ fromIntegral . (n .>>.) <$> [(bytes - 1) * 8, (bytes - 2) * 8 .. 0]

-- | Pad the message to be in 512-chunks
pad :: B.ByteString -> B.ByteString
pad msg = msg <> B.pack [0x80] <> B.replicate (zeros `div` 8) 0 <> lengthAs64BitInt
  where
    zeros = (512 - 64 - bits - 1) `mod` 512
    lengthAs64BitInt = wordToByteString 8 (fromIntegral bits :: Word64)
    bits = B.length msg * 8

-- | Scramble the hash against the next chunk of data
applyChunk :: [Word32] -> [Word32] -> [Word32]
applyChunk hash_in chunk = zipWith (+) hash_in $ foldl round hash_in (zip k w)
  where
    w = chunk ++ [w !! (i - 16) + s0 i + w !! (i - 7) + s1 i | i <- [16 .. 63]]
    s0 i = (w !! (i - 15) `rotateR` 7) `xor` (w !! (i - 15) `rotateR` 18) `xor` (w !! (i - 15) `shiftR` 3)
    s1 i = (w !! (i - 2) `rotateR` 17) `xor` (w !! (i - 2) `rotateR` 19) `xor` (w !! (i - 2) `shiftR` 10)

    round [a, b, c, d, e, f, g, h] (ki, wi) = [t1 + t2, a, b, c, d + t1, e, f, g]
      where
        ss1 = (e `rotateR` 6) `xor` (e `rotateR` 11) `xor` (e `rotateR` 25)
        ss0 = (a `rotateR` 2) `xor` (a `rotateR` 13) `xor` (a `rotateR` 22)
        ch = (e .&. f) `xor` (complement e .&. g)
        maj = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)
        t1 = h + ss1 + ch + ki + wi
        t2 = ss0 + maj
    round _ _ = error "Should never happen"

hash :: B.ByteString -> B.ByteString
hash = foldl1 mappend . map (wordToByteString 4) . foldl applyChunk initialHash . map groupWords . chunksOf 64 . B.unpack . pad

-- | Group by 4 and turn each group to 1 32-bit integer
groupWords :: [Word8] -> [Word32]
groupWords = map (fromIntegral . bytesToInt) . chunksOf 4

-- | Split a list by chunks of size n
chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = take n xs : chunksOf n (drop n xs)

-- Turn a sequence of bytes, containing n bits to an Integer
bytesToInt :: [Word8] -> Integer
bytesToInt bytes = foldr (.|.) 0 $ zipWith (.<<.) (fromIntegral <$> bytes) [bits - 8, bits - 16 .. 0]
  where
    bits = length bytes * 8
