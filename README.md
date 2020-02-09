# Illumio Challenge

## Input 
```
    Rules for network is given through IllumioRules.csv.
    Incoming packets which has to be validated is given through IllumioInputPackets.csv
 ```
    
## Algorithm:
```

    1. Create two dictionaries. One for rules containing IP [__rulesWithoutIPRange] range and one for rules which does not contain IP range [__rulesWithIPRange].
    2. When incoming packets are parsed, first check if given direction + protocol + IP is present as key in the
    __rulesWithoutIPRange. If present, check if the incoming packet port is equal to port of the given rule present as value.
    If true then return to main function else go to step 3.
        Time Complexity : O(1)
    3.  If direction + protocol + IP is present but port for the rule is present as a range then check if the incoming packet port
    is in the range of given ports for the rule. If true then return to main function else go to step 4.
        Time Complexity: O(1)
    4. If direction + protocol + port is present as key in __rulesWithIPRange dictionary then loop through all the IP ranges present
    as the value. For each range of IP address, check if the incoming packet IP address is valid in the given range. If true then return
    else go to step 5.
        Time Complexity: O(N) where N: Number of rules containing only IP addresses as
        Ranges with direction + protocol + port as key
    5. If direction + protocol  is present as key in __rulesWithIPRange dictionary then loop through all the IP ranges present
    as the value.  For each range of IP address, check if the incoming packet IP address is valid in the given range.
    If true, check if the given port for the incoming packet is in range of given ports. If truem then return
    else return False
        Time Complexity: O(N) where N is the number of rules containing both IP addresses as range and ports as range in
        the rule with direction + protocol as key.

    Best Case time complexity: O(1)
    Worst Case Time complexity: O(N) where N being max( number of rules containing both IP Address and ports in range,
     number of rules containing IP Address in range)
```
