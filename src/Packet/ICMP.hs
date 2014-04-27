{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.ICMP where

--imports
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Control.Monad(replicateM)
import Control.Applicative((<$>),(<*>))
import Data.List(foldl')
import Data.Bits(complement)
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I

data ICMP = ICMP 	{_icType	:: Word8
					,_code		:: Word8
					,_checksum	:: Word16
					,_rest		:: B.ByteString
					}

makeLenses ''ICMP

instance Show ICMP where
	show i = unlines ["<ICMP>",
					"type: " ++ show (i^.icType),
					"code: " ++ show (i^.code),
					"checksum: " ++ hex (i^.checksum),
					"rest of header: " ++ show (i^.rest)
					]
calcChecksum::ICMP->Word16
calcChecksum ic = bs2check $ toBytes (ic & checksum .~ 0)

instance Header ICMP where
	toBytes i = runPut $ do
		i^.icType & pW8
		i^.code & pW8
		i^.checksum & pW16
		i^.rest & pB
	getBytes = ICMP <$> gW8 <*> gW8 <*> gW16 <*> gB 4

instance Header (E.Ethernet:+:I.IP:+:ICMP) where
	toBytes (ei:+:ic) = toBytes ei `B.append` toBytes ic
	getBytes = (:+:) <$> (getBytes::Get (E.Ethernet:+:I.IP)) <*>
						(getBytes::Get ICMP)

instance Attachable (E.Ethernet:+:I.IP) ICMP where
	(e:+:i) +++ ic = e:+:((i & I.len +~ 8 & I.protocol .~ 1) & I.calcChecksum) :+: (ic & checksum .~ calcChecksum ic)

icmp = ICMP 0 0 0 $ B.pack [0,0,0,0]

icmpEchoReq = ICMP 8 0 0 $ (runPut $ do pW16 349;pW16 1)

--TODO: some constructors for services.