{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.ARP where

--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Lens
import Control.Applicative((<$>),(<*>))
import Packet.Packet
import qualified Packet.Ethernet as E

data ARP = ARP 	{_hrd	:: Word16
	    		,_pro	:: Word16
		        ,_hln 	:: Word8
		        ,_pln 	:: Word8
		        ,_opcode:: Word16
		        ,_sha 	:: MACAddr
		        ,_spa 	:: IPAddr
		        ,_tha 	:: MACAddr
		        ,_tpa 	:: IPAddr}
--lens magic
makeLenses ''ARP

instance Show ARP where
	show a = unlines ["<ARP>",
			"hardware type: " ++ show (a^.hrd),
			"protocol type: " ++ show (a^.pro),
			"hardware size: " ++ show (a^.hln),
			"protocol size: " ++ show (a^.pln),
			"opcode: " ++ show (a^.opcode),
			"sender mac: " ++ show (a^.sha),
			"sender ip: " ++ show (a^.spa),
			"target mac: " ++ show (a^.tha),
			"target ip: " ++ show (a^.tpa)]

instance Header ARP where
	toBytes a = runPut $ do
		a^.hrd & pW16
		a^.pro & pW16
		a^.hln & pW8
		a^.pln & pW8
		a^.opcode & pW16
		a^.sha & unMac & pB
		a^.spa & unIpa & pW32
		a^.tha & unMac & pB
		a^.tpa & unIpa & pW32
	getBytes = do
		hrd <- gW16
		pro <- gW16
		hln <- gW8
		pln <- gW8
		opcode <- gW16
		sha <- gB 6
		spa <- gW32
		tha <- gB 6
		tpa <- gW32
		return $ ARP hrd pro hln pln opcode (mac sha) (ipa spa) (mac tha) (ipa tpa)

instance Header (E.Ethernet :+: ARP) where
	toBytes (e :+: a) 	= toBytes e `B.append` toBytes a
	getBytes	 		= (:+:) <$> (getBytes::Get E.Ethernet) <*>
									(getBytes::Get ARP)

instance Attachable E.Ethernet ARP where
	e +++ a = (e & E.ethType .~ 0x806) :+: a

arp = ARP 0 0 0 0 0 
		(read "0:0:0:0:0:0"::MACAddr) 
		(read "0.0.0.0"::IPAddr) 
		(read "0:0:0:0:0:0"::MACAddr) 
		(read "0.0.0.0"::IPAddr)