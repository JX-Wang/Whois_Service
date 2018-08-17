#!/usr/bin/env python
#-*- coding:utf-8 -*-
'''
WHOIS信息查询系统
==================
auther		:		wud
data		:		2017/12/17
ver			:		0.1
'''
import tornado.ioloop  # 循环
import tornado.web  # 后端torrnado框架
import whois  # 与whois服务器连接获得域名的whois信息
import requests  # -。-
from time import ctime  # 使用ctime()函数记录操作时间
import MySQLdb  # 使用MySQL存储用户的操作记录
import DNS  # 使用DNS模块获得域名的IP地址
import sys  #
import re  # 正则表达式
import socket

f = open("Data.txt", 'r+')

HOST = '10.245.146.150'
USER = 'root'
PASSWD = 'platform'
PORT = ''
CHARSET = 'utf8'
DATABASE = 'WHOIS_SERVICE'

class MainHandler(tornado.web.RequestHandler):
    """controll"""
    def get(self):
        try:
            self.db = MySQLdb.connect(HOST, USER, PASSWD)
            print 'Connect Success'
        except Exception as e:
            print 'Connect Error ->', str(e)
        try:
            self.cursor = self.db.cursor()
            print self.cursor.execute("USE " + DATABASE)
        except Exception as e:
            if str(e).find("Unknown database"):  # 为创建的数据库对象
                self.cursor.execute("CREATE DATABASE IF NOT EXISTS " + DATABASE)
                self.cursor.execute("USE " + DATABASE)
                sql = """CREATE TABLE whois_record(
                        Domain CHAR(20) NOT NULL primary key,
                        Domain_ip CHAR(20),
                        User_ip CHAR(20),
                        User_addr CHAR(50),
                        Query_time CHAR(20),
                        Whois_info TEXT)"""
                self.cursor.execute(sql)
        User_ip = socket.gethostbyname(socket.gethostname())
        try:
            http_url = "http://www.ip138.com/ips138.asp?ip="+User_ip+"&action=2"
            # print http_url
            addr_html = requests.get(http_url)
            addr_html.encoding = addr_html.apparent_encoding  # 让爬取得到的数据编码为源网页编码
            # print addr_html.text
            # print type(addr_html.text)
            addr_keyword=re.compile(r'''<td align="center"><ul class="ul1"><li>(.*?)</li>''', re.U|re.S)  # 正则表达式获得对用的地理位置字段
            User_addr =''.join(addr_keyword.findall(addr_html.text))  # 剥离有效的地理位置信息
            # print type(User_addr)
            User_addr = str(User_addr)
            print User_addr
            # print type(ctime())
            # print ctime()
            # 查询表中domain列里出现次数前三的域名
            self.cursor.execute('select Domain, count(3) icount from whois_record group by Domain order by icount desc;')
            info = self.cursor.fetchall()
            #print type(info)
            domain0 = info[0][0]
            domain1 = info[1][0]
            domain2 = info[2][0]
            self.render("WhoisQuery.html", ip=User_ip, address=User_addr, domain1=domain1, domain2=domain2, domain0=domain0)  # render到查询页面
        except:
            # 查询表中domain列里出现次数前三的域名
            try:
                self.cursor.execute('select Domain, count(3) icount from whois_record group by Domain order by icount desc;')
                info = self.cursor.fetchall()
                # print type(info)
                domain0 = info[0][0]
                domain1 = info[1][0]
                domain2 = info[2][0]
            except:
                domain0 = None
                domain1 = None
                domain2 = None
            self.render("WhoisQuery.html", ip=User_ip, address="None", domain1=domain1, domain2=domain2, domain0=domain0)  # render到查询页面


# radio = Domain
class WhoisQuery_Domain(tornado.web.RequestHandler):
    '''whois 请求结果类 '''
    # 从前端的接受post回来的信息
    def post(self):
        User_ip = socket.gethostbyname(socket.gethostname())
        print User_ip
        Query_way = self.get_argument("Query_way")  # 接收从web端返回的处理域名的方式
        if Query_way == "IP":
            print Query_way
            IP = self.get_argument("URL/IP")  # 接收从web端传回的用户输入的IP地址
            # 将域名的IP地址转换为其对应的域名
            '''
            #获得域名的IP地址
            try:
                query = sys.argv[0]#将请求得到的数据存入数组
                DNS.DiscoverNameServers()#获得DNS服务器
                reqobj = DNS.Request(url)#将域名作为变量进行DNS请求
                answerobj = reqobj.req(name = query, qtype = DNS.Type.A)#请求A记录——>IP地址
                if not len(answerobj.answers):#使用len函数来判断DNS服务器是否返回信息
                    print "获取IP失败" 
                for item in answerobj.answers:#剥离得到IP地址
                    A_record = "%s" % item['data']
                print A_record
            except:
                print "IP已制为None"
                A_record = "None"
                pass
            '''
            # url = self.get_argument("whoisinfo")#接收从web端返回的用户输入的域名
            # rurl = "http://" + str(furl)
            print IP, "QueryTime:", ctime()  # 记录IP和查询时间
            # print "Insert Time:",ctime()
            # print type(url)
            whois_info = whois.whois(IP)  # 从whois服务器接收whois信息
            # print whois_info
            # 获取关键字段
            try:
                WUDname = str(whois_info.name)  # 姓名
            except:
                WUDname = "None"
            try:
                WUDtel = str(whois_info.tel)  # 电话
            except:
                WUDtel = "None"
            try:
                WUDstatus = str(whois_info.status)  # 域名状态
            except:
                WUDstatus = "None"
            try:
                WUDname_servers = str(whois_info.name_servers)  # DNS服务器
            except:
                WUDname_servers = "None"
            try:
                WUDcreation_date = str(whois_info.creation_date)  # 创建时间
            except:
                WUDcreation_date = "None"
            try:
                WUDexpiration_date = str(whois_info.expiration_date)  # 截至/到期时间
            except:
                WUDexpiration_date = "None"
            try:
                WUDzipcode = str(whois_info.zipcode)  # 注册商邮编
            except:
                WUDzipcode = "None"
            try:
                WUDcity = str(whois_info.city)  # 注册商城市
            except:
                WUDcity = "None"
            try:
                WUDemails = str(list(whois_info.emails)[1])  # 注册人/注册商邮箱
            except:
                WUDemails = "None"
            try:
                WUDregistrar = str(whois_info.registrar)
            except:
                WUDregistrar = "None"
            try:
                WUDcountry = str(whois_info.country)
            except:
                WUDcountry = "None"
            try:
                WUDstate = str(whois_info.state)
            except:
                WUDstate = "None"
            try:
                WUDaddress = str(whois_info.address)
            except:
                WUDaddress = "None"
            try:
                WUDwhois_server = str(whois_info.whois_server)
            except:
                WUDwhois_server = "None"
            # 将获得的关键字段导入到下一个网页的信息字段，实现信息在网页之间的交互
            self.render("QueryResult_ip.html", ip=IP, country=WUDcountry, address=WUDaddress, state=WUDstate,
                        whois_servers=WUDwhois_server, whoisinfo=whois_info, name=WUDname, tel=WUDtel, status=WUDstatus,
                        name_servers=WUDname_servers, creation_date=WUDcreation_date,
                        expiration_date=WUDexpiration_date, zipcode=WUDzipcode, city=WUDcity, emails=WUDemails,
                        time=ctime(), registrar=WUDregistrar)
            # self.write('form imput is <h>'+ furl +'</h>')
            '''
            except:
                #数据库连接失败就把操作记录记录到数据库中，采用两种存储记录的方式
                print "连接数据库失败，记录已经存入Data.txt文件中"
                print >> f,url + ctime() +str(whois_info)#将用户操作记录到文件中
            '''
            # 通过爬虫获得用户的地理位置
            try:
                http_url = "http://www.ip138.com/ips138.asp?ip=" + User_ip + "&action=2"
                print http_url
                addr_html = requests.get(http_url)
                addr_html.encoding = addr_html.apparent_encoding  # 让爬取得到的数据编码为源网页编码
                # print addr_html.text
                # print type(addr_html.text)
                addr_keyword = re.compile(r'''<td align="center"><ul class="ul1"><li>(.*?)</li>''',
                                          re.U | re.S)  # 正则表达式获得对用的地理位置字段
                User_addr = ''.join(addr_keyword.findall(addr_html.text))[:]  # 剥离有效的地理位置信息
                # print type(User_addr)
                User_addr = str(User_addr)
            except:
                print "客户端地理位置获取失败"
                User_addr = "None"
                print "地理位置已经制为None"
            # 连接数据库记录用户操作，确保在render之后进行数据的记录，避免影响页面跳转
            try:
                # print "正在连接数据..."
                db = MySQLdb.connect(HOST, USER, PASSWD, DATABASE)
                # print "连接数据库成功"
                cursor = db.cursor()
                # print type(ctime())
                # print ctime()
                cursor.execute(
                    'INSERT INTO whois_record (Domain, Domain_ip, User_ip, User_addr, Query_time, Whois_info) values (%s,%s,%s,%s,%s,%s)',
                    ["None", IP, User_ip, User_addr, ctime(), str(whois_info)[:250]])
                db.commit()
                print "操作记录已存入数据库"
            except:
                print "数据库操作失败，记录已经存入Data.txt"
                print >> f, IP + "\t" + ctime() + "\t" + str(whois_info)  # 将用户操作记录到文件

        elif Query_way == "URL":
            print Query_way
            url = self.get_argument("URL/IP")  # 接收从web端传回的是用户输入的域名
            # 获得域名的IP地址
            try:
                query = sys.argv[0]  # 将请求得到的数据存入数组
                DNS.DiscoverNameServers()  # 获得DNS服务器
                reqobj = DNS.Request(url)  # 将域名作为变量进行DNS请求
                answerobj = reqobj.req(name=query, qtype=DNS.Type.A)  # 请求A记录——>IP地址
                if not len(answerobj.answers):  # 使用len函数来判断DNS服务器是否返回信息
                    print "获取IP失败"
                print answerobj
                print answerobj.answers
                for item in answerobj.answers:  # 剥离得到IP地址
                    A_record = "%s" % item['data']
                print A_record
            except Exception as e:
                print "IP已制为None -> result", str(e)
                A_record = "None"
                pass
            # url = self.get_argument("whoisinfo")#接收从web端返回的用户输入的域名
            # rurl = "http://" + str(furl)
            print url, "QueryTime:", ctime()  # 记录域名和查询时间
            # print "Insert Time:",ctime()
            # print type(url)
            whois_info = whois.whois(url)  # 从whois服务器接收whois信息
            # print whois_info
            # 获取关键字段
            try:
                WUDname = str(whois_info.name)  # 姓名
            except:
                WUDname = "None"
            try:
                WUDtel = str(whois_info.tel)  # 电话
            except:
                WUDtel = "None"
            try:
                WUDstatus = str(whois_info.status)  # 域名状态
            except:
                WUDstatus = "None"
            try:
                WUDname_servers = str(whois_info.name_servers)  # DNS服务器
            except:
                WUDname_servers = "None"
            try:
                WUDcreation_date = str(whois_info.creation_date)  # 创建时间
            except:
                WUDcreation_date = "None"
            try:
                WUDexpiration_date = str(whois_info.expiration_date)  # 截至/到期时间
            except:
                WUDexpiration_date = "None"
            try:
                WUDzipcode = str(whois_info.zipcode)  # 注册商邮编
            except:
                WUDzipcode = "None"
            try:
                WUDcity = str(whois_info.city)  # 注册商城市
            except:
                WUDcity = "None"
            try:
                WUDemails = str(whois_info.emails)  # 注册人/注册商邮箱
            except:
                WUDemails = "None"
            try:
                WUDregistrar = str(whois_info.registrar)
            except:
                WUDregistrar = "None"
            try:
                WUDcountry = str(whois_info.country)
            except:
                WUDcountry = "None"
            try:
                WUDstate = str(whois_info.state)
            except:
                WUDstate = "None"
            try:
                WUDaddress = str(whois_info.address)
            except:
                WUDaddress = "None"
            try:
                WUDwhois_server = str(whois_info.whois_server)
            except:
                WUDwhois_server = "None"
            # 将获得的关键字段导入到下一个网页的信息字段，实现信息在网页之间的交互
            self.render("QueryResult_domain.html", ip=A_record, country=WUDcountry, address=WUDaddress, state=WUDstate,
                        whois_servers=WUDwhois_server, whoisinfo=whois_info, Domain=url, name=WUDname, tel=WUDtel,
                        status=WUDstatus, name_servers=WUDname_servers, creation_date=WUDcreation_date,
                        expiration_date=WUDexpiration_date, zipcode=WUDzipcode, city=WUDcity, emails=WUDemails,
                        time=ctime(), registrar=WUDregistrar)
            # self.write('form imput is <h>'+ furl +'</h>')
            '''
            except:
                #数据库连接失败就把操作记录记录到数据库中，采用两种存储记录的方式
                print "连接数据库失败，记录已经存入Data.txt文件中"
                print >> f,url + ctime() +str(whois_info)#将用户操作记录到文件中
            '''
            # 通过爬虫获得用户的地理位置
            try:
                http_url = "http://www.ip138.com/ips138.asp?ip=" + User_ip + "&action=2"
                print http_url
                addr_html = requests.get(http_url)
                addr_html.encoding = addr_html.apparent_encoding  # 让爬取得到的数据编码为源网页编码
                # print addr_html.text
                # print type(addr_html.text)
                addr_keyword = re.compile(r'''<td align="center"><ul class="ul1"><li>(.*?)</li>''',
                                          re.U | re.S)  # 正则表达式获得对用的地理位置字段
                User_addr = ''.join(addr_keyword.findall(addr_html.text))  # 剥离有效的地理位置信息
                # print type(User_addr)
                User_addr = str(User_addr)
                print User_addr
            except:
                print "客户端地理位置获取失败"
                User_addr = "None"
                print "地理位置已经制为None"
            # 连接数据库记录用户操作，确保在render之后进行数据的记录，避免影响页面跳转
            try:
                # print "正在连接数据..."
                db = MySQLdb.connect(HOST, USER, PASSWD, DATABASE, charset=CHARSET)
                # print "连接数据库成功"
                cursor = db.cursor()
                # print type(ctime())
                # print ctime()
                cursor.execute(
                    'INSERT INTO whois_record (Domain, Domain_ip, User_ip, User_addr, Query_time, Whois_info) values (%s,%s,%s,%s,%s,%s)',
                    [str(url), A_record, User_ip, User_addr, ctime(), str(whois_info)[:250]])
                db.commit()
                print "操作记录已存入数据库"
            except:
                print "数据库操作失败，记录已经存入Data.txt"
                print >> f, url + "\t" + ctime() + "\t" + str(whois_info)  # 将用户操作记录到文件


application = tornado.web.Application([
    (r"/", MainHandler),  # 一旦监听到80端口被访问，就将查询页面传递给用户
    (r"/search", WhoisQuery_Domain),  # 用户输入Domain后，程序交到WhoisQuery_Domain，从而来获得域名whois信息
    # (r"/serch?=ip",WhoisQuery_IP),#用户输入IP地址，程序教到WhoisQuery_IP,从而获得域名的whois信息
])

if __name__ == "__main__":
    port = 8012  # http默认80端口
    print "Whois Query System Running ..."
    print "Listen Port", port
    application.listen(port)  # 监听port，一旦port被访问就render到WhoisQuery.html
    tornado.ioloop.IOLoop.instance().start()  # 循环
