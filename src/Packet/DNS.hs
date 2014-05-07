{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.DNS where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Control.Applicative((<$>),(<*>))
import Data.Bits(testBit,shiftR,shiftL,(.|.),(.&.))
import Packet.Packet
import qualified Packet.Ethernet as E
