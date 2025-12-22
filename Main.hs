-- Credits to https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Main where

import Data.Bits ((.&.), (.>>.))
import Data.List (unfoldr)
import Numeric (showHex)
import System.Random (randomR, randomRIO)
import Text.Printf (printf)

-- | [(x,y) | (y^2 - x^3 - a*x - b) `mod` modulus == 0, 4 * a^3 + 27 * b^2 /= 0] <> [0]
data Curve = Curve
  { modulus :: Integer,
    a :: Integer,
    b :: Integer,
    basePoint :: Point,
    order :: Integer,
    cofactor :: Integer
  }

data Point = ZeroPoint | Point {x :: Integer, y :: Integer} deriving (Show, Eq)

curve :: Curve -- secp256k1
curve =
  Curve
    { modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, -- a big prime, 2^256 - 2^32 - 977, Mersenne-like (for efficiency)
      a = 0, -- For efficiency
      b = 7, -- smallest positive integer with a prime number of points
      basePoint =
        Point
          { x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, -- nothing-up-my-sleeve agreed upon point, doesn't really matter
            y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
          },
      order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, -- amount of points in the group, got that with Schoof’s algorithm
      cofactor = 1 -- cofactor * cyclic_multiplicative_subgroup_order = order
    }

-- | get (x,y,gcd) such that ax + by = gcd
extEuclid :: Integer -> Integer -> (Integer, Integer, Integer)
extEuclid 0 b = (0, 1, b)
extEuclid a b = (y1 - x1 * (b `div` a), x1, gcd)
  where
    (x1, y1, gcd) = extEuclid (b `mod` a) a

-- | get x such that (x * k) % p == 1
-- basically, 1/k
inverseMod :: Integer -> Integer -> Integer
inverseMod 0 _ = error "divisionByZero"
inverseMod k p
  | k < 0 = p - inverseMod (-k) p
  | g == 1 = (x `mod` p + p) `mod` p
  | otherwise = error $ printf "%d and %d are not coprime, somehow gcd=%d" k p g
  where
    -- "x * k + yp = gcd" becomes x * k == 1 (mod p) because gcd==1 and yp % p == 0
    (x, _, g) = extEuclid k p

-- | Check if the curve contains a given point
isOnCurve :: Point -> Bool
isOnCurve ZeroPoint = False
isOnCurve Point {x, y} = (y * y - x * x * x - curve.a * x - curve.b) `mod` curve.modulus == 0

-- | Return the negative of a point
neg :: Point -> Point
neg ZeroPoint = ZeroPoint
neg Point {x, y} = Point x (negate y `mod` curve.modulus)

-- | Add two points together according to the group law
add :: Point -> Point -> Point
add p ZeroPoint = p
add ZeroPoint p = p
add p1 p2
  | not $ isOnCurve p1 = error $ show p1 <> " is not on curve"
  | not $ isOnCurve p2 = error $ show p2 <> " is not on curve"
  | p1.x == p2.x && p1.y /= p2.y = ZeroPoint
  | otherwise = Point (xIntersect `mod` curve.modulus) (negate yIntersect `mod` curve.modulus)
  where
    -- slope of the line p1->p2
    m =
      if p1.x == p2.x
        then (3 * p1.x * p1.x + curve.a) * inverseMod (2 * p1.y) curve.modulus -- p1 == p2 -- Got that from taking the derivative
        else (p1.y - p2.y) * inverseMod (p1.x - p2.x) curve.modulus -- p1 /= p2 - really just slope! multiplying by the inverse modulus is just division
    xIntersect = m * m - p1.x - p2.x
    yIntersect = p1.y + m * (xIntersect - p1.x)

-- | k * point computed using the double-and-add algorithm
scalarMultiply :: Integer -> Point -> Point
scalarMultiply _ ZeroPoint = ZeroPoint
scalarMultiply k p
  | k `mod` curve.order == 0 = ZeroPoint
  | k < 0 = scalarMultiply (-k) (neg p)
  | otherwise = foldl add ZeroPoint $ unfoldr handleBit (k, p)
  where
    handleBit :: (Integer, Point) -> Maybe (Point, (Integer, Point))
    handleBit (k, acc) = if k == 0 then Nothing else Just (if k .&. 1 == 1 then acc else ZeroPoint, (k .>>. 1, acc `add` acc))

mkKeypair :: IO (Integer, Point)
mkKeypair = do
  privateKey <- randomRIO (1, curve.order)
  let publicKey = scalarMultiply privateKey curve.basePoint
  return (privateKey, publicKey)

testKeyExchange :: IO ()
testKeyExchange = do
  (alicePrivate, alicePublic) <- mkKeypair
  putStrLn $ "Alice's private key: " <> showHex alicePrivate ""
  putStrLn $ (const "Alice's public key: " <> showHex alicePublic.x <> const ", " <> showHex alicePublic.y) ""

  (bobPrivate, bobPublic) <- mkKeypair
  putStrLn $ "Bob's private key: " <> showHex bobPrivate ""
  putStrLn $ (const "Bob's public key: " <> showHex bobPublic.x <> const ", " <> showHex bobPublic.y) ""

  let secret1 = scalarMultiply alicePrivate bobPublic
  let secret2 = scalarMultiply bobPrivate alicePublic
  putStrLn $ if secret1 == secret2 then "Secrets match!" else "Mismatch: " <> show secret1 <> " vs " <> show secret2

main :: IO ()
main = do
  testKeyExchange
