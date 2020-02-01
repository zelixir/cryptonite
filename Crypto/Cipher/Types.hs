-- |
-- Module      : Crypto.Cipher.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Symmetric cipher basic types
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Cipher.Types
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , BlockCipher128(..)
    , DataUnitOffset
    , KeySizeSpecifier(..)
    -- , cfb8Encrypt
    -- , cfb8Decrypt
    -- * AEAD functions
    , AEADMode(..)
    , CCM_M(..)
    , CCM_L(..)
    , module Crypto.Cipher.Types.AEAD
    -- * Initial Vector type and constructor
    , IV
    , makeIV
    , nullIV
    , ivAdd
    -- * Authentification Tag
    , AuthTag(..)
    , module Crypto.Cipher.Types.Stream
    ) where

import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.Block
import Crypto.Cipher.Types.Stream
import Crypto.Cipher.Types.AEAD
