{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Network.UDP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Control.Applicative((<$>),(<*>))
import Control.Monad(replicateM)
import Data.Bits(complement)
import Data.List(foldl')
import Network.Packet
import qualified Network.Ethernet as E
import qualified Network.IP as I

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
calcChecksum::I.IP->UDP->Word16->Word16
calcChecksum = ((bs2check .) .) . pseudoH

pseudoH::I.IP->UDP->Word16->B.ByteString
pseudoH i u ulen = runPut $ do
				i^.I.source & unIpa & pW32
				i^.I.dest & unIpa & pW32
				(0::Word8) & pW8
				i^.I.protocol & pW8
				ulen & pW16 --udp header (+payload) length.
				u & checksum .~ 0 & toBytes & pB


instance Header UDP where
	toBytes u = runPut $ do
		u^.source & pW16
		u^.dest & pW16
		u^.len & pW16
		u^.checksum & pW16
	getBytes = UDP <$> gW16 <*> gW16 <*> gW16 <*> gW16

instance Header ((E.Ethernet :+: I.IP) :+: UDP) where
	toBytes (ei :+: u) = toBytes ei `B.append` toBytes u
	getBytes = (:+:) <$> (getBytes::Get (E.Ethernet:+:I.IP)) <*>
						(getBytes::Get UDP)

instance Attachable (E.Ethernet:+:I.IP) UDP where
	(e:+:i) +++ u = e:+:((i & I.len +~ 8 & I.protocol .~ 17) & I.calcChecksum) :+: (u & checksum .~ calcChecksum i u 8)

udp = UDP 0 0 8 0