# Advanced_computer_network
ACN 高等電腦網路 (TCP/IP)
- TCP擁塞控制演算法
- 有三項主要狀態
  - Slow Start (SS)
  - Congestion Avoidance (CA)
  - Fast Recovery (FR)
- SS、CA都是TCP必須執行的元素，兩者的差異只在於回應收到ACK時它們增加cwnd大小的方式。
- 相較於CA，SS會較快速地增加cwnd的大小。FR對於TCP傳送端則是建議性的，而非強制性的。
