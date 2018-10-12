# Whois_Service
基于web的whois查询服务
* author@wud-WangJunx
* data@2017/12/17
* Harbin Institute Of Technology at Weihai
* Cyberspace Security
* 基于python-whoisf库进行whois探测  #  基于tornado框架
* 支持ip反查  #  目前反查效果比较差，只是实现了框架
* 支持数据库存取  #  使用前要安装mysqk-python库 一般需要使用apt-get install libmysqlclient-dev 安装info.egg包
* 支持数据记录
* 首页
* ![image](https://github.com/WangJunx/Whois-Service/blob/master/index.png)
* 通过domain查询
* ![image](https://github.com/WangJunx/Whois-Service/blob/master/show.png)
* 通过ip反查
* ![image](https://github.com/WangJunx/Whois-Service/blob/master/ip_whois.png)
* mysql的数据记录
* ![image](https://github.com/WangJunx/Whois-Service/blob/master/mysql.png)
* 在查询界面，默认使用URL进行查询，可以选择查询模式为IP查询，当然IP反查的效果并不是特别好，需要进一步的优化，除此以外，对于查询到的信息会在数据库中进行记录，关键信息domain、host、hsot_addr、query_time、whois_result会在数据库中进行记录，当存入数据库出现问题，则会选择部分数据记录在文件Data.txt中。

### CONTACT

wjx.wud@gmail.com
wud@wangjunx.top

[WJX的博客](http://www.wangjunx.top)
