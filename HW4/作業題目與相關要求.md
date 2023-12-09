# hw4
## Rules
1. 請在Ubuntu 22.04 下完成本次作業。
2. 請使用C 語言完成本次作業，請提供Makefile來編譯你的程式。
## requirements
1. Hint:
   - Supposedly, you need to refer source code of traceroute to learn how to create an ICMP message and send it out to some host. However, you are not allowed to paste and copy source code of traceroute.
2. Motivation
   - Expanding ring search (ERS): The ERS is an effective way of finding a route between a source node and a route node. A route node is referred to as either the destination or the node that can offer the route information to the destination. As a controlled flooding technique, ERS is used frequently in reactive routing protocols. Starting typically in a predefined small searching area, the ERS conducts a new search from the source node in an enlarged searching region each time if no route node is found. This incremental searching process continues until a route node is found or the maximum searching area is reached. The search in ERS is performed with flooding involving rebroadcasts through intermediate nodes in a continuous and relay fashion, and it is like a search zone expanding gradually, ring by ring, from a small ring to a large one.
   - The source node in ERS initializes the flooding and controls the searching area in each extended flooding as well as the maximum searching area. Two control signals, RREQ (Route REQuest) and RREP (Route REPly), are used in ERS to effectively control the flooding. To minimize flooding, a time-to-live (TTL) mechanism is adopted by ERS. The TTL sequence determines the order of flooding search, and it may be assigned with an increment at a specified value, a fixed value of 1 or 2, or a random value. Fig. 1 shows how a set of flooding regions are controlled by a sequence of predefined TTL values of 1, 2, 3, … , and n.
   - The TTL-based ERS suffers from an energy inefficiency. As it can be seen from Fig. 1, if no RREP is received by the source node, the source node will rebroadcast a RREQ with an increased TTL value. The rebroadcasting of a new RREQ from the source node each time introduces energy waste. A redundancy happens in the area overlapped with the previously covered searching area.
This may happen many times before a route node is found or an entire network is searched.
3. 結果呈現:
    - In this homework, you are asked to implement a basic privative of ERS which is similar to traceroute. It outputs the router of a given hop-distance to a special destination, and its usage is “prog hop-distance destination”. For example, “prog 3 140.117.11.1” is to look for the 3-hop far router from the source host on the way to 140.117.11.1 host. 
