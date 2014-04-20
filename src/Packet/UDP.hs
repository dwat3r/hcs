{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.UDP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Control.Applicative((<$>),(<*>))
import Control.Monad(replicateM)
import Data.Bits(complement)
import Data.List(foldl')
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I

data UDP = UDP 	{_source	:: Word16
				,_dest		:: Word16
				,_len		:: Word16
				,_checksum	:: Word16}
--make lens:
makeLenses ''UDP

instance Show UDP where
	show u = unlines ["<UDP>",
				"source port: " ++ show (u^.source),
				"destination port: " ++ show (u^.dest),
				"header (+payload) length: " ++ show (u^.len),
				"checksum: " ++ hex (u^.checksum)
				]
--calculate checksum for ip :+: udp:
calcChecksum::I.IP->UDP->Word16
calcChecksum i u = complement $ foldl' (+) 0 $ ws i u
	where
		ws::I.IP->UDP->[Word16]
		ws i u = runGet (replicateM ((fromIntegral $ B.length $ pseudoH i u)`div` 2) gW16) $ pseudoH i u
		pseudoH::I.IP->UDP->B.ByteString
		pseudoH i u = runPut $ do
						i^.I.source & unIpa & pW32
						i^.I.dest & unIpa & pW32
						(0::Word8) & pW8
						i^.I.protocol & pW8
						u^.len & pW16 --udp header (+payload) length.
						u & checksum .~ 0 & toBytes & pB


instance Header UDP where
	toBytes u = runPut $ do
		u^.source & pW16
		u^.dest & pW16
		u^.len & pW16
		u^.checksum & pW16
	fromBytes = runGet $ UDP <$> gW16 <*> gW16 <*> gW16 <*> gW16

--instance Header (I.IP :+: UDP) where
--	toBytes (i :+: u) = toBytes i `B.append` toBytes u
--	fromBytes bs = 	(fromBytes (B.take (fromIntegral $ iphlen bs) bs)::I.IP):+:
--					(fromBytes (B.drop (fromIntegral $ iphlen bs) bs)::UDP)
--		where
--			iphlen::B.ByteString->Word8
--			iphlen = snd . I.unpackvh . B.head

instance Header ((E.Ethernet :+: I.IP) :+: UDP) where
	toBytes (ei :+: u) = toBytes ei `B.append` toBytes u
	fromBytes bs = 	(fromBytes (B.take (fromIntegral $ I.eihlen bs) bs)::E.Ethernet:+:I.IP) :+:
					(fromBytes (B.drop (fromIntegral $ I.eihlen bs) bs)::UDP)

--instance Attachable I.IP UDP where
--	i +++ u = (i & I.len +~ (u^.len) & I.protocol .~ 17) :+: u & calcChecksum

instance Attachable (E.Ethernet:+:I.IP) UDP where
	ei +++ u = (setr ei ((I.len +~ 4).(I.protocol .~ 17))) :+: (u & checksum .~ calcChecksum (getr ei) u)

udp = UDP 0 0 4 0