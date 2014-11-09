--send arp request using packet sockets

import Network.Socket.NetPacket
import Network.Socket

import qualified Data.ByteString as B
import Numeric
--ethernet :: B.ByteString
--ethernet = B.pack [
hex :: (Show a,Integral a) => a -> String
hex a = showHex a ""

brdcast = HWAddr $ B.pack [0xff,0xff,0xff,0xff,0xff,0xff]

sockLL :: IFIndex -> SockAddrLL
sockLL ifx = SockAddrLL (LLProtocol 0x608) ifx hwTypeEther packetOtherhost brdcast
main = do
		s <- socket AF_PACKET Datagram ethProtocolAll
		ifx <- getInterfaceIndex s "enp0s3"
		setPacketOption s packetAddMembership $ PacketMReq ifx mrPromisc brdcast
		ret <- sendToLL s (B.pack [0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x90,0xe6,0xba,0x4e,0x7b,0x0b,0x0a,0x00,0x02,0x04,0xff,0xff,0xff,0xff,0xff,0xff,0x0a,0x00,0x02,0x01]) $ sockLL ifx
		(sal,bs) <- recvFromLL s 28
		print $ map hex $ B.unpack $ bs
