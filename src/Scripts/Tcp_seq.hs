-- Description: A program using PCS to analyze a pcap file and graph
-- the sequence numbers
module Tcp_seq where

import Network.Pcap hiding (sendPacket)
import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Control.Lens
import Connector
import Control.Monad
import Control.Concurrent(threadDelay)
import Packet.Packet
--import qualified Packet.Ethernet as E
--import qualified Packet.IP as I
--import qualified Packet.TCP as TCP
--import qualified Packet.Payload as P

