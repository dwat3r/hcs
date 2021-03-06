{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Network.TCP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Control.Monad(replicateM)
import Control.Applicative((<$>),(<*>))
import Data.Bits(testBit,complement,shiftR,(.|.),bit)
import Data.List(foldl')
import Network.Packet
import qualified Network.Ethernet as E
import qualified Network.IP as I
import Debug.Trace

data TCP = TCP {_source			:: Word16
				,_dest 			:: Word16
				,_seqnum 		:: Word32
				,_acknum 		:: Word32
				,_offset		:: Word8
				,_flags 		:: Word8 --8 bit field for 8 bits :3
				,_window 		:: Word16
				,_checksum	 	:: Word16
				,_urgp 			:: Word16
				,_options	 	:: B.ByteString}
--lens magic:
makeLenses ''TCP

instance Show TCP where
	show t = unlines ["<TCP>",
				"source port: " ++ show (t^.source),
				"destination port: " ++ show (t^.dest),
				"sequence number: " ++ show (t^.seqnum),
				"acknowledgement number: " ++ show (t^.acknum),
				"header length: " ++ show (t^.offset & ((*4) . (`shiftR` 4))) ++ " bytes",
				"flags: " ++ show (t^.flags & showFlags),
				"window size: " ++ show (t^.window),
				"checksum: " ++ hex (t^.checksum),
				"urgent pointer: " ++ show (t^.urgp),
				"options: " ++ show (t^.options)
				]
--pretty print flags field:
showFlags::Word8->[String]
showFlags f = snd $ unzip $ filter (fst) $ zip (toL f) ["CWR","ECN","URG","ACK","PSH","RST","SYN","FIN"]
	where
		toL::Word8->[Bool]
		toL f = map (testBit f) [7,6..0]
--TODO:flagsetter function
setFlags :: [String]->Word8
setFlags flags = foldl1 ((.|.)) [bit (snd ref) |ref<-[("CWR",7),("ECN",6),("URG",5),("ACK",4),("PSH",3),("RST",2),("SYN",1),("FIN",0)],f<-flags,f==fst ref]

--predicates for tcp flags:
cwr::Word8->Bool
cwr f = testBit f 7
ecn::Word8->Bool
ecn f = testBit f 6
urg::Word8->Bool
urg f = testBit f 5
ack::Word8->Bool
ack f = testBit f 4
psh::Word8->Bool
psh f = testBit f 3
rst::Word8->Bool
rst f = testBit f 2
syn::Word8->Bool
syn f = testBit f 1
fin::Word8->Bool
fin f = testBit f 0
--helper for getting tcp header length:
tcplen::TCP->Word16
tcplen t = t^.offset & (*4) & fromIntegral

--calculate checksum for ip :+: tcp:
calcChecksum::I.IP->TCP->Word16->Word16
calcChecksum = ((bs2check .) .) . pseudoH

pseudoH::I.IP->TCP->Word16->B.ByteString
pseudoH i t tlen = runPut $ do 
				i^.I.source & unIpa & pW32
				i^.I.dest & unIpa & pW32
				(0::Word8) & pW8
				i^.I.protocol & pW8
				tlen & pW16 --tcp header (+payload) length.
				t & checksum .~ 0 & toBytes & pB
--TODO: flag setters
instance Header TCP where
	toBytes t = runPut $ do
		t^.source & pW16
		t^.dest & pW16
		t^.seqnum & pW32
		t^.acknum & pW32
		t^.offset & pW8
		t^.flags & pW8
		t^.window & pW16
		t^.checksum & pW16
		t^.urgp & pW16
		t^.options & pB
	getBytes = do
		source <- gW16
		dest <- gW16
		seqnum <- gW32
		acknum <- gW32
		offset <- gW8
		flags <- gW8
		window <- gW16
		checksum <- gW16
		urgp <- gW16
		options <- gB (fromIntegral (((offset `shiftR` 4)-5)*4))
		return $ TCP source dest seqnum acknum
			(offset `shiftR` 4) flags window checksum urgp options

instance Header ((E.Ethernet :+: I.IP) :+: TCP) where
	toBytes (ei :+: t) = toBytes ei `B.append` toBytes t
	getBytes = (:+:) <$>	(getBytes::Get (E.Ethernet:+:I.IP)) <*>
							(getBytes::Get TCP)

instance Attachable (E.Ethernet:+:I.IP) TCP where
	(e:+:i) +++ t = e:+:((i & I.len +~ (t & tcplen) & I.protocol .~ 6) & I.calcChecksum) :+: (t & checksum .~ calcChecksum i t (tcplen t))

tcp = TCP 0 0 0 0 5 0 0 0 0 B.empty

--TODO: write aux functions for setting options field
