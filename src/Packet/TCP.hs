{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.TCP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Control.Monad(replicateM)
import Data.Bits(testBit,complement)
import Data.List(foldl')
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I

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
				"header length: " ++ show (t^.offset & (*4)) ++ " bytes",
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
--helper for calculating options field length:
--offset->number of Word8 -s
oplen h | h<=5 = 0
		| True = (h-5)*4
--calculate checksum for ip :+: tcp:
calcChecksum::(I.IP:+:TCP)->(I.IP:+:TCP)
calcChecksum (i :+: t) = i:+: (t & checksum .~ (i:+:t & calc))
	where
		calc::(I.IP:+:TCP)->Word16
		calc = foldl' ( (+) . complement) 0 . ws
		ws::(I.IP:+:TCP)->[Word16]
		ws it = runGet (replicateM ((fromIntegral $ B.length $ pseudoH it)`div`2) gW16) $ pseudoH it
		pseudoH::(I.IP:+:TCP)->B.ByteString
		pseudoH (i:+:t) = runPut $ do 
						i^.I.source & unIpa & pW32
						i^.I.dest & unIpa & pW32
						(0::Word8) & pW8
						i^.I.protocol & pW8
						toBytes t & B.length & fromIntegral & pW16 --tcp header (+payload) length.
						t & checksum .~ 0 & toBytes & pB

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
	fromBytes = runGet $ do
		source <- gW16
		dest <- gW16
		seqnum <- gW32
		acknum <- gW32
		offset <- gW8
		flags <- gW8
		window <- gW16
		checksum <- gW16
		urgp <- gW16
		options <- gB (fromIntegral $ oplen offset)
		return $ TCP source dest seqnum acknum
			offset flags window checksum urgp options

instance Header (I.IP :+: TCP) where
	toBytes (i :+: t) = toBytes i `B.append` toBytes t
	fromBytes bs = 
		where
			iphlen::B.ByteString->Int
			iphlen = 

instance Header (E.Ethernet :+: (I.IP :+: TCP)) where

instance Attachable I.IP TCP
instance Attachable E.Ethernet (I.IP :+: TCP)

tcp = TCP 0 0 0 0 0 0 0 0 0 B.empty