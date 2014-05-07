{-# LANGUAGE TypeOperators #-}
module Arpwhohas where

import Network.Pcap hiding (sendPacket)
import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Control.Lens
import Connector
import Control.Monad
import Control.Concurrent(threadDelay)
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I
import qualified Packet.ARP as A
import System.Environment
import System.Exit
import Network.Info
 
usage   = putStrLn "Usage: Arpwhohas interface ip"
noIface = putStrLn "Error: no interface found with given name"
exit    = exitWith ExitSuccess
die     = exitWith (ExitFailure 1)
--source ip,source mac,dest ip
packet::IPAddr->MACAddr->String->(E.Ethernet:+:A.ARP)
packet i m t=(E.ethernet & E.source .~ m
                        & E.dest .~ (read "ff:ff:ff:ff:ff:ff"::MACAddr)) +++
            (A.arp  & A.opcode .~ 1
                    & A.sha .~ m
                    & A.spa .~ i
                    & A.tha .~ (read "00:00:00:00:00:00"::MACAddr)
                    & A.tpa .~ (read t::IPAddr))

main = do
    args <- getArgs
    if length args /= 2 then usage >> die
    else do
        im <- iface $ args!!0
        if isJust im == False then noIface
        else do
            i <- openIface $ args!!0
            --setFilter i "arp" True 0
            sendPacket i (packet (fst $ fromJust im) (snd $ fromJust im) (args!!1))
            printPacket i >> exit

iface::String->IO (Maybe (IPAddr,MACAddr))
iface s = do
    ifaces  <- getNetworkInterfaces
    return $ toThrees $ listToMaybe $ filter (\n->s==name n) ifaces
        where
            toThrees::Maybe NetworkInterface->Maybe (IPAddr,MACAddr)
            toThrees mn = case isJust mn of
                        True -> Just $ (toIP $ ipv4 $ fromJust mn,toMac $ Network.Info.mac $ fromJust mn)
                        False -> Nothing
            toMac::MAC->MACAddr
            toMac (MAC a b c d e f) = MACA $ B.pack [a,b,c,d,e,f]
            toIP::IPv4->IPAddr
            toIP (IPv4 i) = IPA $ flipBO32 i