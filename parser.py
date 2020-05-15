#this first version parser
import re
from collections import Counter
import csv

def reader(filename):
    with open(filename) as file:
        log = file.read()
        list = log.split("\n")
    return list
def find_ip(list, regexp):
    ip = []
    for i in range(len(list)):
        a = re.findall(regexp, list[i], flags = re.IGNORECASE)

        if a:
            ip.append(a[0])
    return ip

def find(list, regexp):
    ip = []
    for i in range(len(list)):
        a = re.findall(regexp, list[i], flags = re.IGNORECASE)

        if a:
            ip.append(list[i])
    return ip

def find_dos(list, regexp):
    ip = []
    regexp_time = r":\d{1,2} "
    regexp_time_sec = r"\d{1,2}"
    for i in range(len(list)-2):
        a = re.findall(regexp, list[i], flags = re.IGNORECASE)
        a_time = re.findall(regexp_time, list[i])
        a_time_sec = int(re.findall(regexp_time_sec, a_time[0])[0])

        for j in range(1,10):
            b = re.findall(regexp, list[i + j], flags=re.IGNORECASE)

            if a!=b:
                break
            if j == 9:
                b_time = re.findall(regexp_time, list[i+j])
                b_time_sec = int(re.findall(regexp_time_sec, b_time[0])[0])

                if b_time_sec - a_time_sec <=3:
                    ip.append(list[i])

                i += 10

                '''не надо, иначе будет работать 10 минут
                k=0
                b = re.findall(regexp, list[i + k], flags=re.IGNORECASE)
                while a==b:
                    i+=1
                    k+=1
                    b = re.findall(regexp, list[i + k], flags=re.IGNORECASE)
                print(i)'''
    return ip


#упорядочивание в словарь
def count(ip_list):
    count = Counter(ip_list)
    return count

#write in csv file
def write_csv(count):
    with open("output.csv", "w") as csvfile:
        writer = csv.writer(csvfile)

        header = ['IP', "Frequently"]
        writer.writerow(header)#пишещь в каждую строчку ip и его частоту
        for key in count:
            writer.writerow((key, count[key]))

def write(filename, data, format='w'):
    with open(filename,format) as file:
        for i in range(len(data)):
            a = str(data[i]) + "\n\n"
            file.write(a)

if __name__=="__main__":
    file = reader("access_small.log")
    #regexp_ip = r"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    #search 403 error
    regexp_status_403 = r"HTTP/*.*\" 403 "  # reg = HTTP/1.1" 200
    status_403 = find(file, regexp_status_403)
    write("403.txt", status_403)
    print("403 response - ", len(status_403))

    #search 401 error
    regexp_status_401 = r"HTTP/*.*\" 401 "  # reg = HTTP/1.1" 200
    status_401 = find(file, regexp_status_401)
    write("401.txt", status_401)
    print("401 response - ",len(status_401))

    #поиск sql-injection
    regexp_sql = r"select"
    status_sql_select = find(file, regexp_sql)
    write("sql.txt", status_sql_select)
    print("select injection - ",len(status_sql_select))
    #можно проверять сколько там других признаков sql инъекций

    regexp_sql = r"information_schema"
    status_sql = find(file, regexp_sql)
    write("sql.txt", status_sql, "a")
    print("infornation_schema injection - ",len(status_sql))

    '''
    regexp_sql = r"union"
    status_sql = find(file, regexp_sql)
    write("sql.txt", status_sql, "a")
    print(len(status_sql))'''


    #поиск dos атак
    regexp_dos_file = r"/[\S]{0,1000} HTTP/\d.\d"  # reg = HTTP/1.1" 200
    status_dos = find_dos(file, regexp_dos_file)
    write("dos.txt", status_dos)
    print("dos - ", len(status_dos))

    #сортировка по ip адресам
    '''ip=find_ip(status_403, regexp_ip)
    print(count(ip))
    write("ip.txt",ip)'''
