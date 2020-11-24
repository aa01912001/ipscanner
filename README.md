# ipscanner
object: scan hosts on the same subnet.

  The scanner sends ICMP echo request to all the other subnet IP addresses. For
example, let your host’s IP address is 140.117.171.148 and netmask is 255.255.255.0.
ICMP echo request (type 8) is sent to 140.117.171.1~140.117.171.254 (except itself)
respectively, and the ICMP echo reply (type 0) is caught if the host is alive on the
subnet. This is assuming that ICMP is enabled (Ubuntu 18.04 enable by default). Then
the hosts will automatically send ICMP echo reply when ICMP echo requests are
received. 

![](https://i.imgur.com/gAVXuvX.png)

Send ICMP echo request packet :
Fill the IP header according to the following format:
1. Header length = calculate by youself
2. Total length = calculate by youself
3. Id = 0
4. Flag = don’t fragment
5. TTL = 1
6. Protocol = ICMP

![](https://i.imgur.com/SUkI1tM.png)

Fill the ICMP packet according to the following format:
1. Checksum (You can let OS do it.)
2. ID: process id
3. Sequence number: Starting from 1, increase one by one.
