{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.Payload where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Data.Char(chr)
import Control.Lens
import Control.Applicative((<$>),(<*>))
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.ARP as A
import qualified Packet.IP as I
import qualified Packet.TCP as T
import qualified Packet.UDP as U
import qualified Packet.ICMP as IC

newtype Payload = Payload {_content :: B.ByteString}

--make lens:
makeLenses ''Payload
paylen::Payload->Word16
paylen p = p^. content & B.length & fromIntegral

instance Show Payload where
	show p = unlines ["<Payload>",
				"content: " ++ show (p^.content & B.unpack & map (chr . fromIntegral))]


instance Header Payload where
	toBytes p = p^.content
	getBytes = Payload <$> grB

instance Header (E.Ethernet :+:I.IP :+: U.UDP :+: Payload) where
	toBytes (eiu :+: p) = toBytes eiu `B.append` toBytes p
	getBytes = (:+:) <$> (getBytes::Get (E.Ethernet:+:I.IP:+:U.UDP)) <*>
						(getBytes::Get Payload)

instance Header (E.Ethernet :+:I.IP :+: T.TCP :+: Payload) where
	toBytes (eit :+: p) = toBytes eit `B.append` toBytes p
	getBytes = (:+:) <$> (getBytes::Get (E.Ethernet:+:I.IP:+:T.TCP)) <*>
						(getBytes::Get Payload)
					
instance Header (E.Ethernet:+:I.IP:+:IC.ICMP:+:Payload) where
	toBytes (eiic :+: p) = toBytes eiic `B.append` toBytes p
	getBytes = (:+:) <$> (getBytes::Get (E.Ethernet:+:I.IP:+:IC.ICMP)) <*>
						(getBytes::Get Payload)
					
instance Attachable (E.Ethernet:+:I.IP:+:T.TCP) Payload where
	(e:+:i:+:t) +++ p = e:+:((i & I.len +~paylen p) & I.calcChecksum) :+: (t & T.checksum .~ T.calcChecksum i t (tcpaylen t p)) :+: p
		where
			tcpaylen::T.TCP->Payload->Word16
			tcpaylen t p = T.tcplen t + paylen p 

instance Attachable (E.Ethernet:+:I.IP:+:U.UDP) Payload where
	(e:+:i:+:u) +++ p = e :+: ((i & I.len +~paylen p) & I.calcChecksum) :+: (u & U.len +~ paylen p & U.checksum .~ U.calcChecksum i u) :+: p

instance Attachable (E.Ethernet:+:I.IP:+:IC.ICMP) Payload where
	(e:+:i:+:ic) +++ p = e :+: ((i & I.len +~paylen p) & I.calcChecksum) :+: (ic & IC.checksum .~ ccIC ic p) :+: p
		where
			ccIC::IC.ICMP->Payload->Word16
			ccIC ic p = bs2check $ toBytes (ic & IC.checksum .~ 0) `B.append` toBytes p


payload = Payload $ B.pack [0,0,0,0]