import dns.resolver
import dns.query
import dns.name
import sys
import time


# List of root servers
# Source : https://www.iana.org/domains/root/servers
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

Key = [
    '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29 euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v 58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8 g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37 NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/E fucp2gaDX6RS6CXpoY68LsvPVjR0ZSwz z1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgu l0sGIcGOYl7OyQdXfZ57relSQageu+ip AdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1 dfwhYB4N7knNnulqQxA+Uk1ihz0=',
    '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=']

# storing start time in start
start = time.time()

def main():
    global domain_name
    domain_name = sys.argv[1]

    d_name = domain_name.split('.')
    if d_name[0] != 'www':
        query_var = domain_name
    else:
        query_var = ''
        for i in d_name[1:]:
            query_var = query_var + i + '.'
        
    try:
        
        # output format
        # Question

        print('QUESTION SECTION:')
        print('\t')
        print(str(domain_name) + " " + "IN" + " " + str('A'))
        print('\t')

        # Answer
        print('ANSWER SECTION:')
        print('\t')
        # print(str(domain_name) + " " + "IN" + " " + str('A')+" "+resp[0])
        resp = MyDNSSEC_resolver(query_var,'')
        if type(resp)!=str:
            print(str(domain_name) + " " + "IN" + " " + str('A')+" "+resp[0])
        else:
            print(resp)

        print('\t')
        end=(time.time() - start) * 1000
        print('EXECUTION TIME: %s msec' % (end))
        print('ON: ' + str(time.ctime()))
        print('MSG SIZE rcvd: ' + str(len(str(resp))+len(domain_name)))
    except:
        print(' Unable to Resolve')


def MyDNSSEC_resolver(host,resp):
    rec_prev = []
    list_servers = rootServerLst
    j = 0
    n = 0
    Key_set = set(Key)
    
    while len(list_servers) > 0 and j < 4:
        # split input for parsing each level
        p_var = host.strip(".").split('.')
        qname = ''
        j += 1
        if n == 0:
            qname = '.'
        else:
            qname = ".".join(p_var[-n:])
            qname += "."
        n += 1

        for rootserver in list_servers:
            # split rootserver for parsing
                d_name = str(rootserver).split(' ')
                # making query message
                query = dns.message.make_query(host,dns.rdatatype.A,want_dnssec=True)
                if len(d_name[-1]) > 16:
                    continue
                # return response obtained after sending query using TCP
                resp = dns.query.tcp(query,d_name[-1])
                list_servers = resp.additional
                # rootKey
                # Making KEYQUERY message
                keyQuery = dns.message.make_query(qname,dns.rdatatype.DNSKEY,want_dnssec=True)
                # return response obtained after sending KEYQUERY using TCP
                keyresp = dns.query.tcp(keyQuery,d_name[-1])

                

                if qname == '.':
                    KSK = list()
                    for i in range(3):
                        if '257' in str(keyresp.answer[0][i]):
                            KSK.append(str(keyresp.answer[0][i]))

                    verified = False
                    for i in Key_set: 
                        if i in KSK:
                            verified=True
                            break
                    if not verified:
                        return 'DNSSec verification failed'
                else:
                    name = dns.name.from_text(qname)
                    if len(resp.answer) == 0:
                        if len(resp.authority) == 3 and len(keyresp.answer) != 0:
                            
                            dns.dnssec.validate(resp.authority[1], resp.authority[2], {name: keyresp.answer[0]})
                        else:
                            return 'DNSSEC unsupported'
                    else:
                        pass
                if qname != '.':
                    if len(keyresp.answer) != 0:
                        matched = False
                        for i in range(len(keyresp.answer[0])):
                            if '257' in str(keyresp.answer[0][i]):
                                makeKey = keyresp.answer[0][i]
                                cur1 = str(dns.dnssec.make_ds(name=qname,key=makeKey,algorithm='SHA256')).split(' ')
                                cur2 = str(dns.dnssec.make_ds(name=qname,key=makeKey,algorithm='SHA1')).split(' ')
                                prev_split = str(rec_prev).split(' ')
                                if cur1[-1] == prev_split[-1] or cur2[-1] == prev_split[-1]:
                                    matched = True
                                    break
                                else:
                                    continue
                        if matched:
                            if len(resp.answer) > 0 and str(resp.answer[0]).split(" ")[3] == "A":
                                return [str(resp.answer[0]).split(" ")[4]]
                        else:
                            return ' DNSSEC verification failed'
                    else:
                        return 'DNSSEC unsupported'
                else:
                    pass

                if len(resp.authority) > 0:
                    rec_prev = resp.authority[1]
                else:
                    return 'DNSSEC unsupported'

                name = dns.name.from_text(qname)
                if len(keyresp.answer) == 2:
                    try:
                        dns.dnssec.validate(keyresp.answer[0], keyresp.answer[1], {name: keyresp.answer[0]})
                    except dns.dnssec.ValidationFailure:
                        return 'DNSSec verification failed'
                    else:
                        pass
                else:
                    return 'DNSSEC unsupported'
                break

        # Check if answer contains CNAME or IP
        if len(resp.answer) != 0:
            answer = str(resp.answer[0])
            d_name = answer.split(' ')

            # Perform additional resolution upon CNAME
            if d_name[3] == 'CNAME':
                return MyDNSSEC_resolver(d_name[-1],resp)
            else:
                return resp.answer

        # Check if the additional section is empty.
        elif len(resp.additional) == 0:
            # Getting name from authority section
            d_name = str(resp.authority[0]).split(' ')
            # sending for resolution
            list_servers = MyDNSSEC_resolver(d_name[-1],resp)
        else:
            continue


if __name__ == '__main__':
    main()

