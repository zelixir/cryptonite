{-# Language FlexibleInstances, FlexibleContexts, MultiParamTypeClasses, TypeFamilies, FunctionalDependencies, DeriveFunctor, GeneralisedNewtypeDeriving  #-}
-- |
-- Module      : Crypto.Cipher.Types.Stream
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Stream cipher basic types
--
module Crypto.Cipher.Types.Stream where

import           Crypto.Internal.ByteArray     as B
import qualified Data.ByteString.Lazy          as L
import qualified Data.ByteString          as BS

newtype StreamMessage a = StreamMessage { getStreamMessage :: a }
    deriving (Functor, ByteArrayAccess,Ord, Eq, ByteArray, Semigroup, Monoid)

class (Monoid a, ByteArray b) => StreamableMessage a b | a -> b where
    chunk :: Int -> a -> [a]
    toMemory :: a -> b
    toMessage :: b -> a

instance (ByteArray a, Monoid a) => StreamableMessage (StreamMessage a) a where
    chunk _ (StreamMessage bs) | B.length bs == 0 = []
    chunk sz (StreamMessage bs) =
        let (b1, b2) = B.splitAt sz bs
        in  StreamMessage b1 : chunk sz (StreamMessage b2)
    toMemory  = getStreamMessage
    toMessage = StreamMessage

instance StreamableMessage L.ByteString BS.ByteString where
    chunk sz bs | L.null bs = []
                | otherwise = x : chunk sz xs
        where (x, xs) = L.splitAt (fromIntegral sz) bs
    toMemory = L.toStrict
    toMessage = L.fromStrict 


    