{-# LANGUAGE TemplateHaskell #-}
--exports:
module Packet.Ethernet (
		Ethernet(..),
		MAC(..),
		macToBS,
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
			   			  		deriving (Show)
--lens magic
makeLenses ''Ethernet

newtype MAC = M [Word8] 
	deriving (Show) --TODO: smarter

instance Header Ethernet where
	toBytes e = runPut $ do 
		putLazyByteString $ e^.dest
		putLazyByteString $ e^.source
		putWord16be $ e^.ethType
	fromBytes bs = runGet (do
		dest <- getLazyByteString 6
		source <- getLazyByteString 6
		ethType <- getWord16be
		return $ Ethernet dest source ethType) bs

macToBS :: MAC -> B.ByteString
macToBS (M bs) = B.pack bs

ethernet = Ethernet (macToBS $ M [0,0,0,0,0,0]) (macToBS $ M [0,0,0,0,0,0]) 0x800