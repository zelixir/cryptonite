-- |
-- Module      : Crypto.Cipher.Types.Block
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Block cipher basic types
--
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE Rank2Types #-}
-- {-# LANGUAGE IncoherentInstances #-}
module Crypto.Cipher.Types.Block
  (
    -- * BlockCipher
    BlockCipher(..)
  , BlockCipher128(..)
    -- * Initialization vector (IV)
  , IV(..)
  , makeIV
  , nullIV
  , ivAdd
    -- * XTS
  , XTS
    -- * AEAD
  , AEAD(..)
    -- , AEADState(..)
  , AEADModeImpl(..)
  , aeadAppendHeader
  , aeadEncrypt
  , aeadDecrypt
  , aeadFinalize
    -- * CFB 8 bits
    --, cfb8Encrypt
    --, cfb8Decrypt
  )
where

import           Data.Word
import           Crypto.Error
import           Crypto.Cipher.Types.Base
import           Crypto.Cipher.Types.Stream
import           Crypto.Cipher.Types.GF
import           Crypto.Cipher.Types.AEAD
import           Crypto.Internal.ByteArray      ( ByteArrayAccess
                                                , ByteArray
                                                , withByteArray
                                                , Bytes
                                                )
import qualified Crypto.Internal.ByteArray     as B

import           Foreign.Ptr
import           Foreign.Storable

-- | an IV parametrized by the cipher
data IV c = forall byteArray . ByteArray byteArray => IV byteArray
data BlockMode = ECB | CBC | CFB | CTR
data CipherMode = Encrypt | Decrypt

instance BlockCipher c => ByteArrayAccess (IV c) where
  withByteArray (IV z) f = withByteArray z f
  length (IV z) = B.length z
instance Eq (IV c) where
  (IV a) == (IV b) = B.eq a b

-- | XTS callback
type XTS ba cipher
  =  (cipher, cipher)
  -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
  -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
  -> ba               -- ^ Data
  -> ba               -- ^ Processed Data
type CipherWithIV cipher ba r
  =  (StreamableMessage ba r, BlockCipher cipher)
  => cipher
  -> IV cipher
  -> ba
  -> ba
-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize    :: cipher -> Int

    blockEncrypt :: ByteArray ba => cipher -> ba -> ba
    blockDecrypt :: ByteArray ba => cipher -> ba -> ba

    -- | Encrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbEncrypt :: StreamableMessage ba r => cipher -> ba -> ba
    ecbEncrypt cipher = blockCipherGeneric ECB Encrypt cipher undefined
    -- | Decrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbDecrypt :: StreamableMessage ba r => cipher -> ba -> ba
    ecbDecrypt cipher = blockCipherGeneric ECB Decrypt cipher undefined
    -- | encrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcEncrypt :: CipherWithIV cipher ba r
    cbcEncrypt = blockCipherGeneric CBC Encrypt
    -- | decrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcDecrypt :: CipherWithIV cipher ba r
    cbcDecrypt = blockCipherGeneric CBC Decrypt

    -- | encrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbEncrypt :: CipherWithIV cipher ba r
    cfbEncrypt = blockCipherGeneric CFB Encrypt
    -- | decrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbDecrypt :: CipherWithIV cipher ba r
    cfbDecrypt = blockCipherGeneric CFB Decrypt

    -- | combine using the CTR mode.
    --
    -- CTR mode produce a stream of randomized data that is combined
    -- (by XOR operation) with the input stream.
    --
    -- encryption and decryption are the same operation.
    --
    -- input can be of any size
    ctrCombine :: CipherWithIV cipher ba r
    ctrCombine = blockCipherGeneric CTR Encrypt

    -- | Initialize a new AEAD State
    --
    -- When Nothing is returns, it means the mode is not handled.
    aeadInit :: ByteArrayAccess iv => AEADMode -> cipher -> iv -> CryptoFailable (AEAD cipher)
    aeadInit _ _ _ = CryptoFailed CryptoError_AEADModeNotSupported

-- | class of block cipher with a 128 bits block size
class BlockCipher cipher => BlockCipher128 cipher where
    -- | encrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize, and the cipher
    -- need to process 128 bits block only
    xtsEncrypt, xtsDecrypt :: StreamableMessage ba r
               => (cipher, cipher)
               -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
               -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
               -> ba               -- ^ Plaintext
               -> ba               -- ^ Ciphertext

    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize, and the cipher
    -- need to process 128 bits block only
    xtsEncrypt = xtsGeneric blockEncrypt
    xtsDecrypt = xtsGeneric blockDecrypt

-- | Create an IV for a specified block cipher
makeIV :: (ByteArrayAccess b, BlockCipher c) => b -> Maybe (IV c)
makeIV b = toIV undefined
 where
  toIV :: BlockCipher c => c -> Maybe (IV c)
  toIV cipher | B.length b == sz = Just $ IV (B.convert b :: Bytes)
              | otherwise        = Nothing
    where sz = blockSize cipher

-- | Create an IV that is effectively representing the number 0
nullIV :: BlockCipher c => IV c
nullIV = toIV undefined
 where
  toIV :: BlockCipher c => c -> IV c
  toIV cipher = IV (B.zero (blockSize cipher) :: Bytes)

-- | Increment an IV by a number.
--
-- Assume the IV is in Big Endian format.
ivAdd :: IV c -> Int -> IV c
ivAdd (IV b) i = IV $ copy b
 where
  copy :: ByteArray bs => bs -> bs
  copy bs = B.copyAndFreeze bs $ loop i (B.length bs - 1)

  loop :: Int -> Int -> Ptr Word8 -> IO ()
  loop acc ofs p
    | ofs < 0 = return ()
    | otherwise = do
      v <- peek (p `plusPtr` ofs) :: IO Word8
      let accv     = acc + fromIntegral v
          (hi, lo) = accv `divMod` 256
      poke (p `plusPtr` ofs) (fromIntegral lo :: Word8)
      loop hi (ofs - 1) p

runCipherBlock
  :: (BlockCipher c, ByteArray byteArray, BlockCipher cipher)
  => BlockMode
  -> CipherMode
  -> cipher
  -> (IV c, byteArray)
  -> (IV c, byteArray)
runCipherBlock ECB Encrypt cipher (iv, i) = (iv, blockEncrypt cipher i)
runCipherBlock ECB Decrypt cipher (iv, i) = (iv, blockDecrypt cipher i)
runCipherBlock CBC Encrypt cipher (iv, i) =
  let o = blockEncrypt cipher $ B.xor iv i in (IV o, o)
runCipherBlock CBC Decrypt cipher (iv, i) =
  let o = B.xor iv $ blockDecrypt cipher i in (IV i, o)
runCipherBlock CFB Encrypt cipher ((IV iv), i) =
  let o = B.xor i $ blockEncrypt cipher iv in (IV o, o)
runCipherBlock CFB Decrypt cipher ((IV iv), i) =
  let o = B.xor i $ blockEncrypt cipher iv in (IV i, o)
runCipherBlock CTR _ cipher (iv@(IV ivd), i) =
  (ivAdd iv 1, B.xor i (blockEncrypt cipher ivd))

blockCipherGeneric
  :: (BlockCipher cipher, StreamableMessage ba r)
  => BlockMode
  -> CipherMode
  -> CipherWithIV cipher ba r
blockCipherGeneric bmode cmode cipher ivini =
  mconcat . map toMessage . doCipher ivini . map toMemory . chunk
    (blockSize cipher)
 where
  doCipher _ [] = []
  doCipher iv (i : is) =
    let (nextIV, outputMsg) = runCipherBlock bmode cmode cipher (iv, i)
    in  outputMsg : doCipher nextIV is

xtsGeneric
  :: (StreamableMessage ba r, BlockCipher128 cipher)
  => (cipher -> r -> r)
  -> (cipher, cipher)
  -> IV cipher
  -> DataUnitOffset
  -> ba
  -> ba
xtsGeneric f (cipher, tweakCipher) (IV iv) sPoint =
  mconcat . map toMessage . doXts iniTweak . map toMemory . chunk
    (blockSize cipher)
 where
  encTweak = blockEncrypt tweakCipher iv
  iniTweak = iterate xtsGFMul encTweak !! fromIntegral sPoint
  doXts _ [] = []
  doXts tweak (i : is) =
    let o = B.xor (f cipher $ B.xor i tweak) tweak
    in  o : doXts (xtsGFMul tweak) is

{-
-- | Encrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Encrypt :: BlockCipher a => a -> IV a -> B.byteString -> B.byteString
cfb8Encrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbEncrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` out)

-- | Decrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Decrypt :: BlockCipher a => a -> IV a -> B.byteString -> B.byteString
cfb8Decrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbDecrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` B.head m')
-}
