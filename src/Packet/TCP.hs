{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.TCP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
import Packet.Ethernet
import Packet.IP

data TCP = TCP {source			:: Word16
				,_dest 			:: Word16
				,_seqnum 		:: Word32
				,_acknum 		:: Word32
				,_offset		:: Word8
				,_reserved 		:: Word8
				,_flags 		:: Word8 --8 bit field for 8 bits :3
				,_window 		:: Word16
				,_checksum	 	:: Word16
				,_urgp 			:: Word16
				,_options	 	:: B.ByteString}
					deriving Show

makeLenses ''TCP

instance Header TCP where
	toBytes t = undefined
	fromBytes bs = undefined

instance Header (IP :+: TCP) where

instance Header (Ethernet (IP :+: TCP)) where

instance Attachable IP TCP
instance Attachable Ethernet (IP :+: TCP)

tcp = TCP 0 0 0 0 0 0 0 0 0 0 B.empty