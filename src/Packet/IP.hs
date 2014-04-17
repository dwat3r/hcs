{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.IP (
		IP(..),
		toBytes,
		fromBytes,
		ip) where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
import Packet.Ethernet
--representation:
--fields smaller than a byte stores values as big endian
data IP = IP 	{_version 	:: Word8
        	  	,_hlen 		:: Word8
        		,_tos 		:: Word8
        		,_len 		:: Word16
        		,_ipID 		:: Word16
        		,_flags 	:: Word8
        		,_offset 	:: Word16
        		,_ttl 		:: Word8
        		,_protocol 	:: Word8
        		,_checksum 	:: Word16
        		,_source 	:: Word32
        		,_dest 		:: Word32
        		,_options 	:: B.ByteString}
        			deriving (Show)
--lens magic
makeLenses ''IP
--fix...to put bit fields correctly
instance Header IP where
	toBytes i = runPut $ do
		putWord8 $ i^.version
		putWord8 $ i^.hlen
		putWord8 $ i^.tos
		putWord16be $ i^.len
		putWord16be $ i^.ipID
		putWord8 $ i^.flags --FIXME: flags are three bits,fix to correctly put it
		putWord16be $ i^.offset
		putWord8 $ i^.protocol
		putWord16be $ i^.checksum
		putWord32be $ i^.source
		putWord32be $ i^.dest
		putLazyByteString $ i^.options

instance Attachable Ethernet IP where


ip = IP