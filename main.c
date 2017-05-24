/* 
* THIS FILE IS FOR IP FORWARD TEST 
*/ 

#include <iostream>
#include <vector>
#include "sysInclude.h" 

// system support 
extern void fwd_LocalRcv(char *pBuffer, int length); 

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop); 

extern void fwd_DiscardPkt(char *pBuffer, int type); 

extern unsigned int getIpv4Address(); 

// implemented by students 

struct routeTable 	//路由表
{ 
  unsigned int destIP; 	//目的IP地址
  unsigned int mask; 	//子网掩码对应的整数值
  unsigned int masklen; //子网掩码1的个数
  unsigned int nexthop; //下一跳地址
}; 
std::vector<routeTable> m_table; //用vector保存每一个路由表中信息

void stud_Route_Init() 		//路由表初始化 清空
{ 
  m_table.clear(); 
  return; 
} 

void stud_route_add(stud_route_msg *proute) //路由表添加每一项的信息，
{ 
  routeTable newTableItem; 
  newTableItem.masklen = ntohl(proute->masklen); 
  newTableItem.mask = (1<<31)>>(ntohl(proute->masklen)-1); 
  newTableItem.destIP = ntohl(proute->dest)&newTableItem.mask; 
  newTableItem.nexthop = ntohl(proute->nexthop); 
  m_table.push_back(newTableItem); 
  return; 
} 

int stud_fwd_deal(char *pBuffer, int length) 	//获取IP报文后进行处理
{ 

  int IHL = pBuffer[0] & 0xf; 				//获取头部字段长度
  int TTL = (int)pBuffer[8]; 					//获取生存时间TTL
  int destIP = ntohl(*(unsigned int*)(pBuffer+16)); 	//获得目的IP地址

  if(destIP == getIpv4Address()) 				//如果目的IP地址是本机地址，则直接发送给本机进行处理
  { 
    fwd_LocalRcv(pBuffer, length); 
    return 0; 
  } 

  if(TTL <= 0) 				//如果TTL小于0则丢弃该IP报文
 { 
    fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR); 
    return 1; 
  }	

  bool isMatch = false; 		//用于判断是否在路由表中找到了对应的匹配项
  unsigned int longestMatchLen = 0; //用于寻找最长的匹配
  int bestMatch = 0; 			//用于保存最终匹配对应的路由表中的条目号

  for(int i = 0; i < m_table.size(); i ++) //寻找路由表中的最佳匹配
  { 
    if(m_table[i].masklen > longestMatchLen && m_table[i].destIP == (destIP & m_table[i].mask)) 
    { 						//目标IP地址和子网掩码按位取&结果为子网的地址（即可对应到路由表中的项）
      bestMatch = i; 
      isMatch = true; 
      longestMatchLen = m_table[i].masklen; 
    } 
  } 

  if(isMatch) 			//如果在路由表中找到了匹配项，则构造IP数据包发送
  { 
    char *buffer = new char[length]; 
    memcpy(buffer,pBuffer,length); 
    buffer[8]--; //TTL - 1 		//重新TTL字段
    int sum = 0; 
    unsigned short int localCheckSum = 0; 
    for(int j = 0; j < 2 * IHL; j ++) //重写校验和字段
    { 
      if (j != 5) { 
        sum = sum + (buffer[j*2]<<8) + (buffer[j*2+1]); 
      } 

    } 

    while((unsigned(sum) >> 16) != 0) 
    sum = unsigned(sum) >> 16 + sum & 0xffff; 

    localCheckSum = htons(0xffff - (unsigned short int)sum); 
    memcpy(buffer+10, &localCheckSum, sizeof(unsigned short)); 

    fwd_SendtoLower(buffer, length, m_table[bestMatch].nexthop); 
    return 0; 				//发送IP报文给下一层
  } 
  else 
  { 
    fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE); 
    return 1; 
  }
  return 1; 
}

