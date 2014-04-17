{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.UDP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
import Packet.Ethernet
import Packet.IP

data UDP = UDP 	{_source	:: Word16
				,_dest		:: Word16
				,_len		:: Word16
				,_checksum	:: Word16}
					deriving Show

makeLenses ''UDP

instance Header UDP where
	toBytes u = undefined
	fromBytes bs = undefined
instance Header (IP :+: UDP) where
	toBytes (i :+: u) = undefined
	fromBytes bs = undefined

instance Header (Ethernet :+: IP :+: UDP) where
	toBytes (e :+: i :+: u) = undefined
	fromBytes bs = undefined

instance Attachable IP UDP
instance Attachable Ethernet (IP :+: UDP)

udp = UDP 0 0 0 0