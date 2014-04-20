{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.Payload where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.ARP as A
import qualified Packet.IP as I
import qualified Packet.TCP as T
import qualified Packet.UDP as U

newtype Payload = Payload {_content :: B.ByteString}

--make lens:
makeLenses ''Payload

instance Show Payload where
	show p = unlines ["<Payload>",
				"content: " ++ show (p^.content)]
--ez a payload barmihez passzolhato,jelenleg az "undefined" fuggveny metaforaja
instance Header Payload where
	toBytes p = p^.content

instance Header (E.Ethernet :+:I.IP :+: U.UDP :+: Payload) where
	toBytes (eiu :+: p) = toBytes eiu `B.append` toBytes p
	fromBytes bs = 	(fromBytes (B.take (fromIntegral eiulen bs) bs)::E.Ethernet:+:I.IP:+:U.UDP) :+:
					(fromBytes (B.drop (fromIntegral eiulen bs) bs)::Payload)
					where
						eiulen bs = 14 + 
instance Header (E.Ethernet :+:I.IP :+: T.TCP :+: Payload) where
	toBytes (eit :+: p) = toBytes eit `B.append` toBytes p
	fromBytes bs = 	(fromBytes (B.take 14 bs)::E.Ethernet) :+:
					(fromBytes (B.drop 14 bs)::I.IP:+:T.TCP:+:Payload)

--for convenience:
instance Header (E.Ethernet :+: Payload) where
	toBytes (e :+: p) = toBytes e `B.append` toBytes p
	fromBytes bs = 	(fromBytes (B.take 14 bs)::E.Ethernet) :+:
					(fromBytes (B.drop 14 bs)::Payload)

instance Header (E.Ethernet :+: (I.IP :+: Payload)) where
	toBytes (e :+: ip) = toBytes e `B.append` toBytes ip
	fromBytes bs = 	(fromBytes (B.take 14 bs)::E.Ethernet) :+:
					(fromBytes (B.drop 14 bs)::I.IP:+:Payload)

instance Attachable (E.Ethernet:+:I.IP:+:T.TCP) Payload where

instance Attachable (E.Ethernet:+:I.IP:+:U.UDP) Payload where

--for convenience:
instance Attachable E.Ethernet Payload where

instance Attachable (E.Ethernet:+:I.IP) Payload where

payload = Payload B.empty