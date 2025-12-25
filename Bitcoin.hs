{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

-- Interferes with the OverloadedLists extension
{-# HLINT ignore "Use list comprehension" #-}

module Bitcoin where

-- This all can be optimized with the bytestring builder if wanted
import Data.Bits (Bits, (.>>.))
import qualified Data.ByteString as BS
import EC (Point (..), Signature (Signature), mkKeypairFromString)
import qualified RIPEMD160
import qualified SHA256

data IsCompressed = Compressed | NotCompressed

data IsHashed = Hashed | NotHashed

-- | Serialize the key into just 20 bytes
encodePublicKey :: IsHashed -> IsCompressed -> Point -> BS.ByteString
-- We take hash of a hash for two reasons:
-- 1. SHA256 can be attacked by length extension attacks ???
-- 2. RIPEMD160 is 20 bytes instead of SHA256's 32 - space efficiency
encodePublicKey Hashed = ((RIPEMD160.hash . SHA256.hash) .) . encodePublicKey'
encodePublicKey NotHashed = encodePublicKey'

encodePublicKey' :: IsCompressed -> Point -> BS.ByteString
encodePublicKey' Compressed key = [if even key.y then 2 else 3] <> SHA256.wordToByteString 32 key.x -- y can be derived from x given the parity
encodePublicKey' NotCompressed key = [4] <> SHA256.wordToByteString 32 key.x <> SHA256.wordToByteString 32 key.y -- elliptic curve coordinates are 32 byte

-- | Transform a sequence of bytes into a human-readable code
base58 :: BS.ByteString -> BS.ByteString
base58 bytes = ones <> encoded
  where
    (zeros, rest) = BS.span (== 0) bytes
    ones = BS.replicate (BS.length zeros) (BS.index alphabet 0)
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encoded = BS.reverse $ BS.unfoldr encode $ SHA256.bytesToInt $ BS.unpack rest
    encode 0 = Nothing
    encode n = Just (BS.index alphabet (fromInteger r), q)
      where
        (q, r) = n `divMod` 58

bitcoinAddress :: Point -> BS.ByteString -> IsCompressed -> BS.ByteString
bitcoinAddress key net compress = base58 $ payload <> checkSum
  where
    version = [if net == "main" then 0 else 0x6f]
    payload = version <> encodePublicKey Hashed compress key
    checkSum = BS.take 4 $ SHA256.hash $ SHA256.hash payload

data Identity = Identity {private :: Integer, public :: Point, address :: BS.ByteString} deriving (Eq, Show)

testIdentity :: BS.ByteString -> Identity
testIdentity string = Identity privateKey publicKey addr
  where
    (privateKey, publicKey) = mkKeypairFromString string
    addr = bitcoinAddress publicKey "test" Compressed

newtype Script = Script {getScript :: [BS.ByteString]}

data TxIn = TxIn
  { prevTx :: BS.ByteString, -- hash256 of prev tx contents
    prevIndex :: Integer, -- UTXO output index in the transaction
    scriptSig :: Script,
    _sequence :: Integer -- Not used
  }

data TxOut = TxOut
  { amount :: Integer, -- In satoshi, 1e-8 of a bitcoin
    scriptPubkey :: Script
  }

data Tx = Tx
  { version :: Integer, -- ???
    ins :: [TxIn],
    outs :: [TxOut],
    locktime :: Integer -- ???
  }

-- | Integral to little endian ByteString
i2LEBS :: (Integral a, Bits a) => Int -> a -> BS.ByteString
i2LEBS bytes n = BS.pack $ fromIntegral . (n .>>.) <$> [0, 8 .. (bytes - 1) * 8]

-- | Integer to little endian ByteString of varying length
i2VarLEBS :: (Integral a, Bits a, Show a) => a -> BS.ByteString
i2VarLEBS i
  | i < 0xfd = SHA256.wordToByteString 1 i
  | i < 0x10000 = [0xfd] <> i2LEBS 2 i
  | i < 0x100000000 = [0xfe] <> i2LEBS 4 i
  | i < 0x10000000000000000 = [0xff] <> i2LEBS 8 i
  | otherwise = error $ "Integer too large: " <> show i

encodeScript :: Script -> BS.ByteString
encodeScript (Script script) = i2VarLEBS (toInteger $ BS.length res) <> res
  where
    res = BS.concat $ map f script
    f x
      | BS.length x == 1 = x
      | BS.length x < 75 = i2LEBS 1 (BS.length x) <> x
      | otherwise = error "Not implemented yet (who needs that?)"

encodeTxOut :: TxOut -> BS.ByteString
encodeTxOut tx = i2LEBS 8 tx.amount <> encodeScript tx.scriptPubkey

data ScriptOverride = None | Pubkey Script | Empty

encodeTxIn :: ScriptOverride -> TxIn -> BS.ByteString
encodeTxIn override tx = BS.concat [BS.reverse tx.prevTx, i2LEBS 4 tx.prevIndex, script override, i2LEBS 4 tx._sequence]
  where
    script None = encodeScript tx.scriptSig
    script (Pubkey s) = encodeScript s
    script Empty = encodeScript $ Script []

encodeTx :: Maybe (Integer, Script) -> Tx -> BS.ByteString
encodeTx sig tx =
  BS.concat $
    [i2LEBS 4 tx.version, i2VarLEBS (length tx.ins)]
      <> ins' sig
      <> [i2VarLEBS $ length tx.outs]
      <> fmap encodeTxOut tx.outs
      <> [i2LEBS 4 tx.locktime, maybe "" (const $ i2LEBS 4 (1 :: Integer)) sig]
  where
    ins' Nothing = encodeTxIn None <$> tx.ins
    ins' (Just (sigIndex, s)) = zipWith (\i -> encodeTxIn $ if i == sigIndex then Pubkey s else Empty) [0 ..] tx.ins

encodeSignature :: Signature -> BS.ByteString
encodeSignature (Signature r s) = [0x30, fromIntegral $ BS.length content] <> content
  where
    content = derN r <> derN s
    derN n = [0x02, fromIntegral $ BS.length val] <> val
      where
        nb = BS.dropWhile (== 0) $ SHA256.wordToByteString 32 n
        val = (if BS.head nb >= 0x80 then [0] else []) <> nb

txId :: Tx -> Integer
txId = SHA256.bytesToInt . BS.unpack . BS.reverse . SHA256.hash . SHA256.hash . encodeTx Nothing
