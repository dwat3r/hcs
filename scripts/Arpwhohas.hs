{-# LANGUAGE TypeOperators #-}
module Arpwhohas where

import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Control.Lens
import Network.Connector
import Network.Packet
import qualified Network.Ethernet as E
import qualified Network.ARP as A
import System.Environment
import System.Exit
--shortcuts to IO actions
usage   = putStrLn "Usage: Arpwhohas interface ip"
noIface = putStrLn "Error: no interface found with given name"
exit    = exitWith ExitSuccess
die     = exitWith (ExitFailure 1)
--source ip,source mac,destination ip
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
        let [iface,dip] = args
        im <- getIPMAC iface
        if isJust im == False then noIface
        else do
            let (sip,smac) = fromJust im
            i <- openIface iface
            filterPacket i "arp"
            sendPacket i $ packet sip smac dip
            printPacket i >> exit