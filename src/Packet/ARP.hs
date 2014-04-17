{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.ARP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packets.Packets
import Packets.Ethernet

data ARP = ARP 	{_hrd 	:: Word16
	    		,_pro 	:: Word16
		        ,_hln 	:: Word8
		        ,_pln 	:: Word8
		        ,_oper 	:: Word16
		        ,_sha 	:: B.ByteString
		        ,_spa 	:: Word32
		        ,_tha 	:: B.ByteString
		        ,_tpa 	:: Word32}
	    			deriving (Show)

makeLenses ''ARP

instance Header (Ethernet :+: ARP) where
	toBytes a = undefined
	fromBytes a = undefined

instance Header ARP where
	toBytes a = undefined
	fromBytes a = undefined

instance Attachable Ethernet ARP where
	e +++ a = undefined