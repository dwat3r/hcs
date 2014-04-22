{-# LANGUAGE TemplateHaskell #-}
--exports:
module Packet.Ethernet where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Packet.Packet
--representation:
data Ethernet = Ethernet 	{_dest 		:: MACAddr
			   			  	,_source 	:: MACAddr
			   			  	,_ethType 	:: Word16}
--lens magic
makeLenses ''Ethernet
--pretty printing mac addresses:
instance Show Ethernet where
	show e = unlines ["<Ethernet>",
					"destination: " ++ show (e^.dest),
					"source: " ++ show (e^.source),
					"type: " ++ hex (e^.ethType)]

instance Header Ethernet where
	toBytes e = runPut $ do 
		e^.dest & unMac & pB
		e^.source & unMac & pB
		e^.ethType & pW16
	getBytes = do
		dest <- gB 6
		source <- gB 6
		ethType <- gW16
		return $ Ethernet (mac dest) (mac source) ethType

ethernet = Ethernet (read "0:0:0:0:0:0"::MACAddr) (read "0:0:0:0:0:0"::MACAddr) 0