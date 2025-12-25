-- I have got enough of bit scrambling in the SHA, there is really nothing interesting anymore.
--
-- So this file is copied from the https://hackage-content.haskell.org/package/ppad-ripemd160-0.1.3/docs/src/Crypto.Hash.RIPEMD160.html#hash
--
-- This is the only time when foreign code was copied into the project
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

-- for spec, see
--
-- https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf

-- |
-- Module: Crypto.Hash.RIPEMD160
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Pure RIPEMD-160 and HMAC-RIPEMD160 implementations for
-- strict and lazy ByteStrings.
module RIPEMD160
  ( -- * RIPEMD-160 message digest functions
    hash,
    hash_lazy,

    -- * RIPEMD160-based MAC functions
    hmac,
    hmac_lazy,
  )
where

import Data.Bits ((.&.), (.|.))
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Builder.Extra as BE
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as BLI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word32, Word64)
import Foreign.ForeignPtr (plusForeignPtr)

-- preliminary utils

-- keystroke saver
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- parse strict ByteString in LE order to Word32 (verbatim from
-- Data.Binary)
--
-- invariant:
--   the input bytestring is at least 32 bits in length
unsafe_word32le :: BS.ByteString -> Word32
unsafe_word32le s =
  (fi (s `BU.unsafeIndex` 3) `B.unsafeShiftL` 24)
    .|. (fi (s `BU.unsafeIndex` 2) `B.unsafeShiftL` 16)
    .|. (fi (s `BU.unsafeIndex` 1) `B.unsafeShiftL` 8)
    .|. (fi (s `BU.unsafeIndex` 0))
{-# INLINE unsafe_word32le #-}

-- utility types for more efficient ByteString management

data SSPair
  = SSPair
      {-# UNPACK #-} !BS.ByteString
      {-# UNPACK #-} !BS.ByteString

data SLPair = SLPair {-# UNPACK #-} !BS.ByteString !BL.ByteString

data WSPair = WSPair {-# UNPACK #-} !Word32 {-# UNPACK #-} !BS.ByteString

-- unsafe version of splitAt that does no bounds checking
--
-- invariant:
--   0 <= n <= l
unsafe_splitAt :: Int -> BS.ByteString -> SSPair
unsafe_splitAt n (BI.BS x l) =
  SSPair (BI.BS x n) (BI.BS (plusForeignPtr x n) (l - n))

-- variant of Data.ByteString.Lazy.splitAt that returns the initial
-- component as a strict, unboxed ByteString
splitAt64 :: BL.ByteString -> SLPair
splitAt64 = splitAt' (64 :: Int)
  where
    splitAt' _ BLI.Empty = SLPair mempty BLI.Empty
    splitAt' n (BLI.Chunk c@(BI.PS _ _ l) cs) =
      if n < l
        then
          -- n < BS.length c, so unsafe_splitAt is safe
          let !(SSPair c0 c1) = unsafe_splitAt n c
           in SLPair c0 (BLI.Chunk c1 cs)
        else
          let SLPair cs' cs'' = splitAt' (n - l) cs
           in SLPair (c <> cs') cs''

-- variant of Data.ByteString.splitAt that behaves like an incremental
-- Word32 parser
--
-- invariant:
--   the input bytestring is at least 32 bits in length
unsafe_parseWsPair :: BS.ByteString -> WSPair
unsafe_parseWsPair (BI.BS x l) =
  WSPair (unsafe_word32le (BI.BS x 4)) (BI.BS (plusForeignPtr x 4) (l - 4))
{-# INLINE unsafe_parseWsPair #-}

-- builder realization strategies

to_strict :: BSB.Builder -> BS.ByteString
to_strict = BL.toStrict . BSB.toLazyByteString

to_strict_small :: BSB.Builder -> BS.ByteString
to_strict_small =
  BL.toStrict
    . BE.toLazyByteStringWith
      (BE.safeStrategy 128 BE.smallChunkSize)
      mempty

-- message padding and parsing

-- this is the standard padding for merkle-damgård constructions; see e.g.
--
--    https://datatracker.ietf.org/doc/html/rfc1320
--    https://datatracker.ietf.org/doc/html/rfc6234
--
--  for equivalent padding specifications for MD4 and SHA2, but note that
--  RIPEMD (and MD4) use little-endian word encodings

-- k such that (l + 1 + k) mod 64 = 56
sol :: Word64 -> Word64
sol l =
  let r = 56 - fi l `rem` 64 - 1 :: Integer -- fi prevents underflow
   in fi (if r < 0 then r + 64 else r)

pad :: BS.ByteString -> BS.ByteString
pad m@(BI.PS _ _ (fi -> l))
  | l < 128 = to_strict_small padded
  | otherwise = to_strict padded
  where
    padded =
      BSB.byteString m
        <> fill (sol l) (BSB.word8 0x80)
        <> BSB.word64LE (l * 8)

    fill j !acc
      | j `rem` 8 == 0 =
          loop64 j acc
      | (j - 7) `rem` 8 == 0 =
          loop64 (j - 7) acc
            <> BSB.word32LE 0x00
            <> BSB.word16LE 0x00
            <> BSB.word8 0x00
      | (j - 6) `rem` 8 == 0 =
          loop64 (j - 6) acc
            <> BSB.word32LE 0x00
            <> BSB.word16LE 0x00
      | (j - 5) `rem` 8 == 0 =
          loop64 (j - 5) acc
            <> BSB.word32LE 0x00
            <> BSB.word8 0x00
      | (j - 4) `rem` 8 == 0 =
          loop64 (j - 4) acc
            <> BSB.word32LE 0x00
      | (j - 3) `rem` 8 == 0 =
          loop64 (j - 3) acc
            <> BSB.word16LE 0x00
            <> BSB.word8 0x00
      | (j - 2) `rem` 8 == 0 =
          loop64 (j - 2) acc
            <> BSB.word16LE 0x00
      | (j - 1) `rem` 8 == 0 =
          loop64 (j - 1) acc
            <> BSB.word8 0x00
      | j `rem` 4 == 0 =
          loop32 j acc
      | (j - 3) `rem` 4 == 0 =
          loop32 (j - 3) acc
            <> BSB.word16LE 0x00
            <> BSB.word8 0x00
      | (j - 2) `rem` 4 == 0 =
          loop32 (j - 2) acc
            <> BSB.word16LE 0x00
      | (j - 1) `rem` 4 == 0 =
          loop32 (j - 1) acc
            <> BSB.word8 0x00
      | j `rem` 2 == 0 =
          loop16 j acc
      | (j - 1) `rem` 2 == 0 =
          loop16 (j - 1) acc
            <> BSB.word8 0x00
      | otherwise =
          loop8 j acc

    loop64 j !acc
      | j == 0 = acc
      | otherwise = loop64 (j - 8) (acc <> BSB.word64LE 0x00)

    loop32 j !acc
      | j == 0 = acc
      | otherwise = loop32 (j - 4) (acc <> BSB.word32LE 0x00)

    loop16 j !acc
      | j == 0 = acc
      | otherwise = loop16 (j - 2) (acc <> BSB.word16LE 0x00)

    loop8 j !acc
      | j == 0 = acc
      | otherwise = loop8 (pred j) (acc <> BSB.word8 0x00)

pad_lazy :: BL.ByteString -> BL.ByteString
pad_lazy (BL.toChunks -> m) = BL.fromChunks (walk 0 m)
  where
    walk !l bs = case bs of
      (c : cs) -> c : walk (l + fi (BS.length c)) cs
      [] -> padding l (sol l) (BSB.word8 0x80)

    padding l k bs
      | k == 0 =
          pure
            . to_strict
            $ bs <> BSB.word64LE (l * 8)
      | otherwise =
          let nacc = bs <> BSB.word8 0x00
           in padding l (pred k) nacc

-- initialization

data Registers = Registers
  { h0 :: !Word32,
    h1 :: !Word32,
    h2 :: !Word32,
    h3 :: !Word32,
    h4 :: !Word32
  }
  deriving (Show)

iv :: Registers
iv = Registers 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0

-- processing

data Block = Block
  { m00 :: !Word32,
    m01 :: !Word32,
    m02 :: !Word32,
    m03 :: !Word32,
    m04 :: !Word32,
    m05 :: !Word32,
    m06 :: !Word32,
    m07 :: !Word32,
    m08 :: !Word32,
    m09 :: !Word32,
    m10 :: !Word32,
    m11 :: !Word32,
    m12 :: !Word32,
    m13 :: !Word32,
    m14 :: !Word32,
    m15 :: !Word32
  }
  deriving (Show)

-- parse strict bytestring to block
--
-- invariant:
--   the input bytestring is exactly 512 bits long
unsafe_parse :: BS.ByteString -> Block
unsafe_parse bs =
  let !(WSPair m00 t00) = unsafe_parseWsPair bs
      !(WSPair m01 t01) = unsafe_parseWsPair t00
      !(WSPair m02 t02) = unsafe_parseWsPair t01
      !(WSPair m03 t03) = unsafe_parseWsPair t02
      !(WSPair m04 t04) = unsafe_parseWsPair t03
      !(WSPair m05 t05) = unsafe_parseWsPair t04
      !(WSPair m06 t06) = unsafe_parseWsPair t05
      !(WSPair m07 t07) = unsafe_parseWsPair t06
      !(WSPair m08 t08) = unsafe_parseWsPair t07
      !(WSPair m09 t09) = unsafe_parseWsPair t08
      !(WSPair m10 t10) = unsafe_parseWsPair t09
      !(WSPair m11 t11) = unsafe_parseWsPair t10
      !(WSPair m12 t12) = unsafe_parseWsPair t11
      !(WSPair m13 t13) = unsafe_parseWsPair t12
      !(WSPair m14 t14) = unsafe_parseWsPair t13
      !(WSPair m15 t15) = unsafe_parseWsPair t14
   in if BS.null t15
        then Block {..}
        else error "ppad-ripemd160: internal error (bytes remaining)"

-- nonlinear functions at bit level
f0, f1, f2, f3, f4 :: Word32 -> Word32 -> Word32 -> Word32
f0 x y z = x `B.xor` y `B.xor` z
{-# INLINE f0 #-}
f1 x y z = (x .&. y) .|. (B.complement x .&. z)
{-# INLINE f1 #-}
f2 x y z = (x .|. B.complement y) `B.xor` z
{-# INLINE f2 #-}
f3 x y z = (x .&. z) .|. (y .&. B.complement z)
{-# INLINE f3 #-}
f4 x y z = x `B.xor` (y .|. B.complement z)
{-# INLINE f4 #-}

-- constants
k0, k1, k2, k3, k4 :: Word32
k0 = 0x00000000 -- 00 <= j <= 15
k1 = 0x5A827999 -- 16 <= j <= 31
k2 = 0x6ED9EBA1 -- 32 <= j <= 47
k3 = 0x8F1BBCDC -- 48 <= j <= 63
k4 = 0xA953FD4E -- 64 <= j <= 79

k0', k1', k2', k3', k4' :: Word32
k0' = 0x50A28BE6 -- 00 <= j <= 15
k1' = 0x5C4DD124 -- 16 <= j <= 31
k2' = 0x6D703EF3 -- 32 <= j <= 47
k3' = 0x7A6D76E9 -- 48 <= j <= 63
k4' = 0x00000000 -- 64 <= j <= 79

-- strict registers pair
data Pair = Pair !Registers !Registers
  deriving (Show)

round1,
  round2,
  round3,
  round4,
  round5 ::
    Word32 -> Word32 -> Registers -> Registers -> Int -> Int -> Pair
round1 x x' (Registers a b c d e) (Registers a' b' c' d' e') s s' =
  let t = B.rotateL (a + f0 b c d + x + k0) s + e
      r0 = Registers e t b (B.rotateL c 10) d
      t' = B.rotateL (a' + f4 b' c' d' + x' + k0') s' + e'
      r1 = Registers e' t' b' (B.rotateL c' 10) d'
   in Pair r0 r1
round2 x x' (Registers a b c d e) (Registers a' b' c' d' e') s s' =
  let t = B.rotateL (a + f1 b c d + x + k1) s + e
      r0 = Registers e t b (B.rotateL c 10) d
      t' = B.rotateL (a' + f3 b' c' d' + x' + k1') s' + e'
      r1 = Registers e' t' b' (B.rotateL c' 10) d'
   in Pair r0 r1
round3 x x' (Registers a b c d e) (Registers a' b' c' d' e') s s' =
  let t = B.rotateL (a + f2 b c d + x + k2) s + e
      r0 = Registers e t b (B.rotateL c 10) d
      t' = B.rotateL (a' + f2 b' c' d' + x' + k2') s' + e'
      r1 = Registers e' t' b' (B.rotateL c' 10) d'
   in Pair r0 r1
round4 x x' (Registers a b c d e) (Registers a' b' c' d' e') s s' =
  let t = B.rotateL (a + f3 b c d + x + k3) s + e
      r0 = Registers e t b (B.rotateL c 10) d
      t' = B.rotateL (a' + f1 b' c' d' + x' + k3') s' + e'
      r1 = Registers e' t' b' (B.rotateL c' 10) d'
   in Pair r0 r1
round5 x x' (Registers a b c d e) (Registers a' b' c' d' e') s s' =
  let t = B.rotateL (a + f4 b c d + x + k4) s + e
      r0 = Registers e t b (B.rotateL c 10) d
      t' = B.rotateL (a' + f0 b' c' d' + x' + k4') s' + e'
      r1 = Registers e' t' b' (B.rotateL c' 10) d'
   in Pair r0 r1

block_hash :: Registers -> Block -> Registers
block_hash reg@Registers {..} Block {..} =
  -- round 1
  --
  -- r(j)      = j (0 ≤ j ≤ 15)
  -- r'(0..15) = 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12
  -- s(0..15)  = 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8
  -- s'(0..15) = 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6
  let !(Pair l00 r00) = round1 m00 m05 reg reg 11 08
      !(Pair l01 r01) = round1 m01 m14 l00 r00 14 09
      !(Pair l02 r02) = round1 m02 m07 l01 r01 15 09
      !(Pair l03 r03) = round1 m03 m00 l02 r02 12 11
      !(Pair l04 r04) = round1 m04 m09 l03 r03 05 13
      !(Pair l05 r05) = round1 m05 m02 l04 r04 08 15
      !(Pair l06 r06) = round1 m06 m11 l05 r05 07 15
      !(Pair l07 r07) = round1 m07 m04 l06 r06 09 05
      !(Pair l08 r08) = round1 m08 m13 l07 r07 11 07
      !(Pair l09 r09) = round1 m09 m06 l08 r08 13 07
      !(Pair l10 r10) = round1 m10 m15 l09 r09 14 08
      !(Pair l11 r11) = round1 m11 m08 l10 r10 15 11
      !(Pair l12 r12) = round1 m12 m01 l11 r11 06 14
      !(Pair l13 r13) = round1 m13 m10 l12 r12 07 14
      !(Pair l14 r14) = round1 m14 m03 l13 r13 09 12
      !(Pair l15 r15) = round1 m15 m12 l14 r14 08 06

      -- round 2
      --
      -- r(16..31) = 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8
      -- r'(16..31) = 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2
      -- s(16..31) = 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12
      -- s'(16..31) = 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11
      !(Pair l16 r16) = round2 m07 m06 l15 r15 07 09
      !(Pair l17 r17) = round2 m04 m11 l16 r16 06 13
      !(Pair l18 r18) = round2 m13 m03 l17 r17 08 15
      !(Pair l19 r19) = round2 m01 m07 l18 r18 13 07
      !(Pair l20 r20) = round2 m10 m00 l19 r19 11 12
      !(Pair l21 r21) = round2 m06 m13 l20 r20 09 08
      !(Pair l22 r22) = round2 m15 m05 l21 r21 07 09
      !(Pair l23 r23) = round2 m03 m10 l22 r22 15 11
      !(Pair l24 r24) = round2 m12 m14 l23 r23 07 07
      !(Pair l25 r25) = round2 m00 m15 l24 r24 12 07
      !(Pair l26 r26) = round2 m09 m08 l25 r25 15 12
      !(Pair l27 r27) = round2 m05 m12 l26 r26 09 07
      !(Pair l28 r28) = round2 m02 m04 l27 r27 11 06
      !(Pair l29 r29) = round2 m14 m09 l28 r28 07 15
      !(Pair l30 r30) = round2 m11 m01 l29 r29 13 13
      !(Pair l31 r31) = round2 m08 m02 l30 r30 12 11

      -- round 3
      --
      -- r(32..47) = 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12
      -- r'(32..47) = 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13
      -- s(32..47) = 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5
      -- s'(32..47) = 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5
      !(Pair l32 r32) = round3 m03 m15 l31 r31 11 09
      !(Pair l33 r33) = round3 m10 m05 l32 r32 13 07
      !(Pair l34 r34) = round3 m14 m01 l33 r33 06 15
      !(Pair l35 r35) = round3 m04 m03 l34 r34 07 11
      !(Pair l36 r36) = round3 m09 m07 l35 r35 14 08
      !(Pair l37 r37) = round3 m15 m14 l36 r36 09 06
      !(Pair l38 r38) = round3 m08 m06 l37 r37 13 06
      !(Pair l39 r39) = round3 m01 m09 l38 r38 15 14
      !(Pair l40 r40) = round3 m02 m11 l39 r39 14 12
      !(Pair l41 r41) = round3 m07 m08 l40 r40 08 13
      !(Pair l42 r42) = round3 m00 m12 l41 r41 13 05
      !(Pair l43 r43) = round3 m06 m02 l42 r42 06 14
      !(Pair l44 r44) = round3 m13 m10 l43 r43 05 13
      !(Pair l45 r45) = round3 m11 m00 l44 r44 12 13
      !(Pair l46 r46) = round3 m05 m04 l45 r45 07 07
      !(Pair l47 r47) = round3 m12 m13 l46 r46 05 05

      -- round 4
      --
      -- r(48..63) = 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
      -- r'(48..63) = 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
      -- s(48..63) = 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
      -- s'(48..63) = 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
      !(Pair l48 r48) = round4 m01 m08 l47 r47 11 15
      !(Pair l49 r49) = round4 m09 m06 l48 r48 12 05
      !(Pair l50 r50) = round4 m11 m04 l49 r49 14 08
      !(Pair l51 r51) = round4 m10 m01 l50 r50 15 11
      !(Pair l52 r52) = round4 m00 m03 l51 r51 14 14
      !(Pair l53 r53) = round4 m08 m11 l52 r52 15 14
      !(Pair l54 r54) = round4 m12 m15 l53 r53 09 06
      !(Pair l55 r55) = round4 m04 m00 l54 r54 08 14
      !(Pair l56 r56) = round4 m13 m05 l55 r55 09 06
      !(Pair l57 r57) = round4 m03 m12 l56 r56 14 09
      !(Pair l58 r58) = round4 m07 m02 l57 r57 05 12
      !(Pair l59 r59) = round4 m15 m13 l58 r58 06 09
      !(Pair l60 r60) = round4 m14 m09 l59 r59 08 12
      !(Pair l61 r61) = round4 m05 m07 l60 r60 06 05
      !(Pair l62 r62) = round4 m06 m10 l61 r61 05 15
      !(Pair l63 r63) = round4 m02 m14 l62 r62 12 08

      -- round 5
      --
      -- r(64..79) = 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
      -- r'(64..79) = 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
      -- s(64..79) = 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
      -- s'(64..79) = 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
      !(Pair l64 r64) = round5 m04 m12 l63 r63 09 08
      !(Pair l65 r65) = round5 m00 m15 l64 r64 15 05
      !(Pair l66 r66) = round5 m05 m10 l65 r65 05 12
      !(Pair l67 r67) = round5 m09 m04 l66 r66 11 09
      !(Pair l68 r68) = round5 m07 m01 l67 r67 06 12
      !(Pair l69 r69) = round5 m12 m05 l68 r68 08 05
      !(Pair l70 r70) = round5 m02 m08 l69 r69 13 14
      !(Pair l71 r71) = round5 m10 m07 l70 r70 12 06
      !(Pair l72 r72) = round5 m14 m06 l71 r71 05 08
      !(Pair l73 r73) = round5 m01 m02 l72 r72 12 13
      !(Pair l74 r74) = round5 m03 m13 l73 r73 13 06
      !(Pair l75 r75) = round5 m08 m14 l74 r74 14 05
      !(Pair l76 r76) = round5 m11 m00 l75 r75 11 15
      !(Pair l77 r77) = round5 m06 m03 l76 r76 08 13
      !(Pair l78 r78) = round5 m15 m09 l77 r77 05 11
      !(Pair l79 r79) = round5 m13 m11 l78 r78 06 11

      !(Registers a b c d e) = l79
      !(Registers a' b' c' d' e') = r79
   in Registers
        (h1 + c + d')
        (h2 + d + e')
        (h3 + e + a')
        (h4 + a + b')
        (h0 + b + c')

-- block pipeline
--
-- invariant:
--   the input bytestring is exactly 512 bits in length
unsafe_hash_alg :: Registers -> BS.ByteString -> Registers
unsafe_hash_alg rs bs = block_hash rs (unsafe_parse bs)

-- register concatenation
cat :: Registers -> BS.ByteString
cat Registers {..} =
  let w64_0 = fi h1 `B.shiftL` 32 .|. fi h0
      w64_1 = fi h3 `B.shiftL` 32 .|. fi h2
   in to_strict_small $
        BSB.word64LE w64_0
          <> BSB.word64LE w64_1
          <> BSB.word32LE h4

-- | Compute a condensed representation of a strict bytestring via
-- RIPEMD-160.
--
-- The 160-bit output digest is returned as a strict bytestring.
--
-- >>> hash "strict bytestring input"
-- "<strict 160-bit message digest>"
hash :: BS.ByteString -> BS.ByteString
hash bs = cat (go iv (pad bs))
  where
    go :: Registers -> BS.ByteString -> Registers
    go !acc b
      | BS.null b = acc
      | otherwise = case unsafe_splitAt 64 b of
          SSPair c r -> go (unsafe_hash_alg acc c) r

-- | Compute a condensed representation of a lazy bytestring via
-- RIPEMD-160.
--
-- The 160-bit output digest is returned as a strict bytestring.
--
-- >>> hash_lazy "lazy bytestring input"
-- "<strict 160-bit message digest>"
hash_lazy :: BL.ByteString -> BS.ByteString
hash_lazy bl = cat (go iv (pad_lazy bl))
  where
    go :: Registers -> BL.ByteString -> Registers
    go !acc bs
      | BL.null bs = acc
      | otherwise = case splitAt64 bs of
          SLPair c r -> go (unsafe_hash_alg acc c) r

-- HMAC -----------------------------------------------------------------------
-- https://datatracker.ietf.org/doc/html/rfc2104#section-2

data KeyAndLen
  = KeyAndLen
      {-# UNPACK #-} !BS.ByteString
      {-# UNPACK #-} !Int

-- | Produce a message authentication code for a strict bytestring,
-- based on the provided (strict, bytestring) key, via RIPEMD-160.
--
-- The 160-bit MAC is returned as a strict bytestring.
--
-- Per RFC 2104, the key /should/ be a minimum of 20 bytes long. Keys
-- exceeding 64 bytes in length will first be hashed (via RIPEMD-160).
--
-- >>> hmac "strict bytestring key" "strict bytestring input"
-- "<strict 160-bit MAC>"
hmac ::
  -- | key
  BS.ByteString ->
  -- | text
  BS.ByteString ->
  BS.ByteString
hmac mk@(BI.PS _ _ l) text =
  let step1 = k <> BS.replicate (64 - lk) 0x00
      step2 = BS.map (B.xor 0x36) step1
      step3 = step2 <> text
      step4 = hash step3
      step5 = BS.map (B.xor 0x5C) step1
      step6 = step5 <> step4
   in hash step6
  where
    !(KeyAndLen k lk)
      | l > 64 = KeyAndLen (hash mk) 20
      | otherwise = KeyAndLen mk l

-- | Produce a message authentication code for a lazy bytestring, based
-- on the provided (strict, bytestring) key, via RIPEMD-160.
--
-- The 160-bit MAC is returned as a strict bytestring.
--
-- Per RFC 2104, the key /should/ be a minimum of 20 bytes long. Keys
-- exceeding 64 bytes in length will first be hashed (via RIPEMD-160).
--
-- >>> hmac_lazy "strict bytestring key" "lazy bytestring input"
-- "<strict 160-bit MAC>"
hmac_lazy ::
  -- | key
  BS.ByteString ->
  -- | text
  BL.ByteString ->
  BS.ByteString
hmac_lazy mk@(BI.PS _ _ l) text =
  let step1 = k <> BS.replicate (64 - lk) 0x00
      step2 = BS.map (B.xor 0x36) step1
      step3 = BL.fromStrict step2 <> text
      step4 = hash_lazy step3
      step5 = BS.map (B.xor 0x5C) step1
      step6 = step5 <> step4
   in hash step6
  where
    !(KeyAndLen k lk)
      | l > 64 = KeyAndLen (hash mk) 20
      | otherwise = KeyAndLen mk l
