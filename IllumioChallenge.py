"""
Algorithm:
    1. Create two dictionaries. One for rules containing IP [rulesWithoutIPRange] range and one for rules which does not contain IP range [rulesWithIPRange].
    2. When incoming packets are parsed, first check if given direction + protocol + IP is present as key in the
    rulesWithoutIPRange. If present, check if the incoming packet port is equal to port of the given rule present as value.
    If true then return to main function else go to step 3.
        Time Complexity : O(1)
    3.  If direction + protocol + IP is present but port for the rule is present as a range then check if the incoming packet port
    is in the range of given ports for the rule. If true then return to main function else go to step 4.
        Time Complexity: O(1)
    4. If direction + protocol + port is present as key in rulesWithIPRange dictionary then loop through all the IP ranges present
    as the value. For each range of IP address, check if the incoming packet IP address is valid in the given range. If true then return
    else go to step 5.
        Time Complexity: O(N) where N: Number of rules containing only IP addresses as
        Ranges with direction + protocol + port as key
    5. If direction + protocol  is present as key in rulesWithIPRange dictionary then loop through all the IP ranges present
    as the value.  For each range of IP address, check if the incoming packet IP address is valid in the given range.
    If true, check if the given port for the incoming packet is in range of given ports. If truem then return
    else return False
        Time Complexity: O(N) where N is the number of rules containing both IP addresses as range and ports as range in
        the rule with direction + protocol as key.

    Best Case time complexity: O(1)
    Worst Case Time complexity: O(N) where N being max( number of rules containing both IP Address and ports in range,
     number of rules containing IP Address in range)



"""
import csv

class fireWallClass:
    # Intializing a dictionary called rules to store the initial given set of rules
    rulesWithoutIPRange = {}
    rulesWithIPRange = {}
    #Constructor for taking csv file name as input
    def __init__(self, rulesFileName):
        """
        The key to be added in dictionary is a combination of inbound/outbound for the given rule +
        the udp/tcp for the given rule + the ip address
        The value will be the port in a list format
        :param rulesFileName: CSV file name which contains the rules for networks.
        """
        with open(rulesFileName) as rulesFile:
            rulesFileReader = csv.reader(rulesFile, delimiter=',')
            for row in rulesFileReader:
                if "-" in row[3] and "-" not in row[2]:
                    if row[0]+"_"+row[1]+"_"+row[2] in self.rulesWithIPRange:
                        self.rulesWithIPRange[row[0]+"_"+row[1]+"_"+row[2]]+=([(row[3].split('-'))])
                    else:
                        self.rulesWithIPRange[row[0] + "_" + row[1]+"_"+row[2]] = [(row[3].split('-'))]
                elif "-" in row[3] and "-" in row[2]:
                    if row[0] + "_" + row[1]in  self.rulesWithIPRange:
                        self.rulesWithIPRange[row[0] + "_" + row[1]]+=([(row[3].split('-'), row[2].split('-'))])
                    else:
                        self.rulesWithIPRange[row[0] + "_" + row[1]] = [(row[3].split('-'), row[2].split('-'))]
                elif "-" in row[2]:
                    y = row[2]
                    self.rulesWithoutIPRange[row[0] + "_" + row[1] + "_" + row[3]] = y.split('-')
                else:
                    self.rulesWithoutIPRange[row[0] + "_" + row[1] + "_" + row[3]] = [row[2]]


    def splitIP(self,address):
        """
        splitIP method takes the address in string format and return integers in tuple format
        :param address: String
        :return: tuple containing integers from address
        """
        return tuple(int(n) for n in address.split('.'))

    def checkIfIPInRange(self,addr, startRange, startEnd):
        """
        Checks if the given IP Address is in the range.
        :param addr: String address which needs to be checked if it is in the range
        :param startRange: String start address in the range
        :param startEnd: String end address in the range
        :return: Boolean value
        """
        return self.splitIP(startRange) <= self.splitIP(addr) <= self.splitIP(startEnd)


    def checkInWithoutIPRange(self, x, port):
        """
        If IP range does not exist and IP is directly present in the dictionary as a key and port is present as a range
        in the value of the dictionary,
        then this method is used for checking if the given port is in the range.
        :param x: String which contains inbound/outbound + udp/tcp + IP address
        :param port: String value which contains port number to be checked for
        :return: Boolean value
        """
        if x in self.rulesWithoutIPRange.keys():
            value = self.rulesWithoutIPRange[x]
            if len(value) == 2:
                if int(port) >= int(value[0]) and int(port)<=int(value[1]):
                    return True
            elif int(value[0]) == int(port):
                return True
            else:
                return False

    def checkInWithIPRange(self, x, port,ip_address):
        """
        If IP is not directly present in the dictionary as a key and port may or may not present as a range
        in the value of the dictionary,
        then this method is used for checking if the given IP and port  exists.
        :param x: String which contains inbound/outbound + udp/tcp
        :param port: String value which contains port number to be checked for
        :param ip_address: String value which contains IP_Address to be checked for
        :return: Boolean value
        """
        if x + "_" +str(port) in self.rulesWithIPRange.keys():
            ipRanges  = self.rulesWithIPRange[x+"_"+str(port)]
            if self.checkIfIPInRange(ip_address, ipRanges[0][0],ipRanges[0][1]):
                return True
        if x in self.rulesWithIPRange.keys():
            ipRanges = self.rulesWithIPRange[x]
            for i in ipRanges:
                if self.checkIfIPInRange(ip_address, i[0][0], i[0][1]) and int(port) <= int(i[1][1]) and int(port)>= int(i[1][0]):
                    return True
        return False

    def acceptPacket(self, direction, protocol, port, ip_address):
        """
        Checks if the given packet is valid or not.
        :param direction: String value inbound or outbound
        :param protocol: String value tcp or udp
        :param port: Value in the range 1-65535
        :param ip_address: IP in the range 0.0.0.0 - 255.255.255.255
        :return: Boolean
        """
        x = direction + "_" + protocol + "_" + ip_address
        if self.checkInWithoutIPRange(x,port):
            return True
        elif self.checkInWithIPRange(direction+"_"+protocol,port,ip_address):
            return True
        else:
            return False


if __name__ == "__main__":
    #The below line takes CSV file which contains Rules for network
     objectCreation = fireWallClass('C:\\Users\maith\.PyCharmCE2019.2\config\scratches\IllumioRules.csv')
    #The below line takes CSV file which contains the packets which needs to be validated
     with open('C:\\Users\maith\.PyCharmCE2019.2\config\scratches\IllumioInputPackets.csv') as rulesFile:
         rulesFileReader = csv.reader(rulesFile, delimiter=',')
         for row in rulesFileReader:
             print(row, " is ", objectCreation.acceptPacket(row[0], row[1], row[2], row[3]))

