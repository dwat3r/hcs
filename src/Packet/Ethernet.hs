{-# LANGUAGE TemplateHaskell #-}
--exports:
module Packet.Ethernet (
		Ethernet(..),
		toBytes,
		fromBytes,
		ethernet) where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
--representation:
data Ethernet = Ethernet 	{_dest 		:: B.ByteString
			   			  	,_source 	:: B.ByteString
			   			  	,_ethType 	:: Word16}
--lens magic
makeLenses ''Ethernet
--pretty printing mac addresses:
instance Show Ethernet where
	show (Ethernet d s t) = "Ethernet: \n" ++
							"destination: " ++ fromMac d ++ "\n" ++
							"source: " ++ fromMac s ++ "\n" ++
							"type: " ++ show t

instance Header Ethernet where
	toBytes e = runPut $ do 
		e^.dest & putLazyByteString
		e^.source & putLazyByteString
		e^.ethType & putWord16be
	fromBytes bs = runGet (do
		dest <- getLazyByteString 6
		source <- getLazyByteString 6
		ethType <- getWord16be
		return $ Ethernet dest source ethType) bs

ethernet = Ethernet (toMac [0,0,0,0,0,0]) (toMac [0,0,0,0,0,0]) 0