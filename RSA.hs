-- TODO: Not tested, at all
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module RSA where

import Data.Bits ((.<<.))
import Data.Ix (Ix (inRange))
import Data.List (find)
import Data.Maybe (fromMaybe)
import System.Random (randomIO, randomR)
import System.Random.Stateful (mkStdGen64)

-- | get (x,y,gcd) such that ax + by = gcd
-- | A little copying is better than a little dependency
extEuclid :: Integer -> Integer -> (Integer, Integer, Integer)
extEuclid 0 b = (0, 1, b)
extEuclid a b = (y1 - x1 * (b `div` a), x1, gcd)
  where
    (x1, y1, gcd) = extEuclid (b `mod` a) a

data PublicKey = PublicKey {n :: Integer, e :: Integer}

data PrivateKey = PrivateKey {n :: Integer, d :: Integer}

encrypt :: PublicKey -> Integer -> Integer
encrypt key msg = (msg ^ key.e) `mod` key.n -- This can be optimized

decrypt :: PrivateKey -> Integer -> Integer
decrypt key msg = (msg ^ key.d) `mod` key.n -- The same

-- | Infinite sequence of primes
primes :: [Integer]
primes = 2 : filter (\p -> not $ any (\p1 -> p `mod` p1 == 0) primes) [3, 5 ..]

-- a and b are coprime iff there is no n such that a mod n == b mod n == 0
coprime :: (Integral a) => a -> a -> Bool
coprime a b = not $ any (\n -> a `mod` n == 0 && b `mod` n == 0) [2 .. min a b]

mkKeypair :: Int -> IO (PublicKey, PrivateKey)
mkKeypair len
  | len < 4 = error "Cannot generate a key of length less than four"
  | otherwise = do
      (p, q) <- choose goodPrimes . mkStdGen64 <$> randomIO
      let stop = (p - 1) * (q - 1)
          -- for decryption to work (m^ed % n == 1) we need ed % phi(n) == 1.
          -- This comes from the fact that "m^phi(n) % m == 1" - Euler's theorem
          -- Here phi is the Euler's totient function
          e = fromMaybe (error "Could not make e") $ find (coprime stop) [3, 3 + 2 .. stop - 1]
          (d, _, _) = extEuclid e stop -- find (\d' -> d' * e `mod` stop == 1) [3, 3 + 2 .. stop - 1]
      return (PublicKey (p * q) e, PrivateKey (p * q) d)
  where
    goodPrimes = takeWhile (<= (1 .<<. (len `div` 2 + 1))) $ dropWhile (< (1 .<<. (len `div` 2 - 1))) primes
    choose [] _ = error $ "Could not find a key for len=" <> show len
    choose primes gen = if null qCandidates then choose primesWithoutP gen0 else (p, q)
      where
        n_min = 1 .<<. (len - 1)
        n_max = (1 .<<. len) - 1
        (pi, gen0) = randomR (0, length primes - 1) gen
        (left, p : right) = splitAt pi primes
        primesWithoutP = left ++ right
        qCandidates = filter (inRange (n_min, n_max) . (* p)) primesWithoutP
        (qi, _) = randomR (0, length qCandidates - 1) gen0 -- Here is an attack vector, because we pass gen0 further
        q = qCandidates !! qi
