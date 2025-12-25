{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module EC where

import Data.Bits ((.&.), (.>>.))
import qualified Data.ByteString as B
import Data.List (unfoldr)
import GHC.Num (integerLog2)
import qualified SHA256
import System.Random (randomRIO)
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

mkKeypairFromString :: B.ByteString -> (Integer, Point)
mkKeypairFromString string = (private, public)
  where
    private = SHA256.bytesToInt (B.unpack string) `mod` curve.order
    public = scalarMultiply private curve.basePoint

hashMessage :: B.ByteString -> Integer
hashMessage = (.>>. extraBits) . SHA256.bytesToInt . B.unpack . SHA256.hash . SHA256.hash
  where
    bits = 256 -- Currently just dead code (our curve is already 256 bit as the hash), present for generality
    extraBits = bits - fromIntegral (integerLog2 curve.order + 1) -- Log rounds down

data Signature = Signature Integer Integer deriving (Eq, Show)

signMessage :: Integer -> B.ByteString -> IO Signature
signMessage privateKey message = do
  k <- randomRIO (1, curve.order)
  let p = scalarMultiply k curve.basePoint
      r = p.x `mod` curve.order
      s_raw = ((hashMessage message + r * privateKey) * inverseMod k curve.order) `mod` curve.order
      s = if s_raw > curve.order `div` 2 then curve.order - s_raw else s_raw
  if s == 0 || r == 0
    then signMessage privateKey message -- Just try again
    else pure $ Signature r s

-- | UNSAFE!!! IN EVERY SENSE OF THIS WORD
signMessage' :: Integer -> B.ByteString -> Integer -> Signature
signMessage' privateKey message k = Signature r s
  where
    p = scalarMultiply k curve.basePoint
    r = p.x `mod` curve.order
    s_raw = ((hashMessage message + r * privateKey) * inverseMod k curve.order) `mod` curve.order
    s = if s_raw > curve.order `div` 2 then curve.order - s_raw else s_raw

verifySignature :: Point -> B.ByteString -> Signature -> Bool
verifySignature publicKey message (Signature r s) = (r `mod` curve.order) == (p.x `mod` curve.order)
  where
    -- p = u1*basePoint + u2*publicKey
    -- p = u1*basePoint + u2*privateKey*basePoint       -- publicKey = privateKey * basePoint
    -- p = (u1 + u2*privateKey) * basePoint             -- distributivity (why?)
    -- p = (hash / s + r / s * privateKey) * basePoint  -- substitute u1, u2
    -- p = (hash + r * privateKey)/s * basePoint        -- substitute u1, u2
    -- p = k * basePoint                                -- s = (hash + r * privateKey) / k
    -- p.x == r                                         -- r = (k * basePoint).x
    -- So we have generated the same point p as in signMessage, but without knowing the secret k.
    w = inverseMod s curve.order
    u1 = (hashMessage message * w) `mod` curve.order
    u2 = (r * w) `mod` curve.order
    p = add (scalarMultiply u1 curve.basePoint) (scalarMultiply u2 publicKey)
