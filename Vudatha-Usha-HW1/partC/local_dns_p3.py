import dns.resolver
import dns.query
import dns.name
import sys
import time
local_dns=[]
google_server=[]
websites=["baidu.com", "wikipedia.org","yandex.ru","facebook.com","tiktok.com"]
# my_resolver=dns.resolver.Resolver()
# print("---------Local DNS Server----------")
# print('\t')
# q=-1
# for i in websites:
#     q+=1
#     ls=[]
#     for j in range(10):
#         start=time.time()
#         answer=my_resolver.resolve(i,"A")
#         ls.append(time.time()-start)
#     local_dns.append(ls)
# for i in range(len(local_dns)):
#     print(local_dns[i])
# print('\t')
# print("-----------Google DNS Server----------")
# q=-1
# my_res=dns.resolver.Resolver(configure=False)
# my_res.nameservers=['8.8.8.8']
# for i in websites:
#     q+=1
#     ls=[]
#     for j in range(10):
#         start=time.time()
#         answer=my_res.resolve(i,"A")
#         ls.append(time.time()-start)
#     google_server.append(ls)
# for i in range(len(google_server)):
#     print(google_server[i])




rootServerLst = []
rootServerLst.append("198.41.0.4")
rootServerLst.append("199.9.14.201")
rootServerLst.append("192.112.36.4")
rootServerLst.append("192.5.5.241")
rootServerLst.append("192.203.230")
rootServerLst.append("199.7.91.13")
rootServerLst.append("198.97.190.53")
rootServerLst.append("192.36.148.17")
rootServerLst.append("192.58.128.30")
rootServerLst.append("193.0.14.129")
rootServerLst.append("199.7.83.42")
rootServerLst.append("202.12.27.33")
rootServerLst.append("192.33.4.12")

start = time.time()
def main():
    websites=["baidu.com", "wikipedia.org","yandex.ru","facebook.com","tiktok.com"]
    mydig=[]
    q=-1
    for i in websites:
        q+=1
        ls=[]
        for j in range(10):
            start=time.time()
            resp=MyResolver(i,"A",'')
            ls.append(time.time()-start)
        mydig.append(ls)
    for i in range(5):
        print(mydig[i])


def MyResolver(host,request,resp):
    j = 0
    any_response = False
    list_servers = rootServerLst
    # Initialised variables to check if any response exists.
    # Iterative resolver iterating through root servers until the ip address is resolved.
    while len(list_servers) > 0 and j < 4:
        j+=1
        for rootserver in list_servers:
            d_name = str(rootserver).split(' ')
            try:
                # Making query message 
                query_var = dns.message.make_query(host,request)
                # return response obtained after sending query using UDP
                resp = dns.query.udp(query_var,d_name[-1],timeout=0.75)
                list_servers = resp.additional
                any_response = True
                break

            except BaseException:
                print('No response. Connecting you to next server')

        # If No response - exit 
        if any_response == False:
            exit()
        # Check if answer contains CNAME or IP
        if len(resp.answer) != 0:

            answer = str(resp.answer[0])
            d_name = answer.split(' ')

            # Perform additional resolution upon CNAME
            if d_name[3] == 'CNAME' and request == 'A':
                return MyResolver(d_name[-1],'A',resp)
            else:
                return resp.answer
        # Check if the additional section is empty.
        elif len(resp.additional)==0:
            # Getting name from authority section
            ans = str(resp.authority[0])
            d_name = ans.split(' ')
            # sending for resolution
            list_servers = MyResolver(d_name[-1],'A',resp)
        else:
            continue



if __name__ == '__main__':
    main()
