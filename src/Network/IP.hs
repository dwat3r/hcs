{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Network.IP where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Control.Applicative((<$>),(<*>))
import Data.Bits(testBit,shiftR,shiftL,(.|.),(.&.))
import Data.List(foldl')
import Network.Packet
import qualified Network.Ethernet as E

--import qualified Test.QuickCheck as Q

--representation:
--fields smaller than a byte stores values as big endian
data IP = IP 	{_version 	:: Word8
        	  	,_hlen 		:: Word8
        		,_tos 		:: Word8
        		,_len 		:: Word16
        		,_ipID 		:: Word16
        		,_flags 	:: Word8
        		,_offset 	:: Word16
        		,_ttl 		:: Word8
        		,_protocol 	:: Word8
        		,_checksum 	:: Word16
        		,_source 	:: IPAddr
        		,_dest 		:: IPAddr
        		,_options 	:: B.ByteString}

--lens magic
makeLenses ''IP
--special flags access:
--stored big endian: rsv,df,mf,0,0....
rsv :: Word8 -> Int
rsv f | testBit f 0 = 1
	  | otherwise = 0
df :: Word8 -> Int
df f | testBit f 1 = 1
	 | otherwise = 0
mf :: Word8 -> Int
mf f | testBit f 2 = 1
	 | otherwise = 0
--TODO:setters for these bits

instance Show IP where
	show i = unlines ["<IP>",
			"version: " ++ show (i^.version),
			"header length: " ++ show (i^.hlen),
			"type of service: " ++ show (i^.tos),
			"total length: " ++ show (i^.len),
			"identification: " ++ show (i^.ipID),
			"flags: ",
			"\treserved: " ++ show (i^.flags & rsv),
			"\tdon't fragment: " ++ show (i^.flags & df),
			"\tmore fragments: " ++ show (i^.flags & mf),
			"fragment offset: " ++ show (i^.offset),
			"protocol: " ++ show (i^.protocol),
			"checksum: " ++ hex (i^.checksum),
			"source :" ++ show (i^.source),
			"destination: " ++ show (i^.dest),
			"options field: " ++ show (i^.options)]

--internal packer,unpacker for [version,hlen] field:
packvh::Word8->Word8->Word8
packvh v h = (h .&. 15) .|. (v `shiftL` 4)
unpackvh::Word8->(Word8,Word8)
unpackvh vh = (vh `shiftR` 4,vh .&. 15)
--internal packer,unpacker for [flags,offset] field:
packfo::Word8->Word16->Word16
packfo f o = fromIntegral (f .&. 7) .|. (o `shiftL` 3)
unpackfo::Word16->(Word8,Word16)
unpackfo fo = (fromIntegral (fo .&. 7),(fo .&. 65528) `shiftR` 3)
--helper for calculating options field length:
--hlen->number of Word8 -s
oplen h | h<=5 = 0
		| True = (h-5)*4
--calculating the checksum field:
calcChecksum ip = ip & checksum .~ (bs2check $ toBytes (ip & checksum .~ 0))



instance Header IP where
	toBytes i = runPut $ do
		packvh (i^.version) (i^.hlen) & pW8
		i^.tos & pW8
		i^.len & pW16
		i^.ipID & pW16
		packfo (i^.flags) (i^.offset) & pW16
		i^.ttl & pW8
		i^.protocol & pW8
		i^.checksum & pW16
		i^.source & unIpa & pW32
		i^.dest & unIpa & pW32
		i^.options & pB
	getBytes = do
		vh <- gW8
		tos <- gW8
		len <- gW16
		ipID <- gW16
		fo <- gW16
		ttl <- gW8
		protocol <- gW8
		checksum <- gW16
		source <- gW32
		dest <- gW32
		options <- gB (fromIntegral $ oplen $ snd $ unpackvh vh)
		return $ IP (fst $ unpackvh vh)
					(snd $ unpackvh vh)
					tos len ipID
					(fst $ unpackfo fo)
					(snd $ unpackfo fo)
					ttl protocol checksum
					(ipa source)
					(ipa dest)
					options

instance Header (E.Ethernet :+: IP) where
	toBytes (e :+: i) = toBytes e `B.append` toBytes i
	getBytes = (:+:) <$> (getBytes::Get E.Ethernet) <*> (getBytes::Get IP)

instance Attachable E.Ethernet IP where
	e +++ i = (e & E.ethType .~ 0x800) :+: i

ip = IP 4 5 0 20 0 0 0 64 0 0
	(read "0.0.0.0"::IPAddr)
	(read "0.0.0.0"::IPAddr)
	B.empty & calcChecksum
--quickcheck tests
prop_pack_unvh x y = (unpackvh $ packvh x y) == (x`mod`16,y`mod`16)

prop_pack_unfo x y = (unpackfo $ packfo x y) == (x`mod` 8,y`mod`8192)