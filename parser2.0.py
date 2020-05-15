"""
#############
#           #
#           #
#           #
#############
#
#
#
#
"""

import re
from collections import Counter

def reader(filename):
    with open(filename) as file:
        log = file.read()
        list = log.split("\n")
    return list

def find(list, regexp):
    response = []
    for i in range(len(list)):
        a = re.findall(regexp, list[i], flags = re.IGNORECASE)

        if a:
            response.append(list[i])
    return response

def return_group(element, number_group):
    return int(element.group(number_group))

def find_time(element_i, element_j):
    if return_group(element_j , 2) - return_group(element_i, 2) == 0 and abs(return_group(element_j, 4) - return_group(element_i, 4) <= 3) or \
            (return_group(element_j , 2) - return_group(element_i, 2) == 1 and return_group(element_j, 4) + 60 - return_group(element_i, 4) <=3):
        return True
    else:
        return False

#https://python-scripts.com/import-re-regular-expression
#https://tproger.ru/translations/regular-expression-python/
def find_element(list, regexp):
    response = []
    for i in range(len(list)):
        a = re.search(regexp, list[i], flags=re.IGNORECASE)

        if a:
            response.append(a)
    return response

def find_dos(list, regexp):
    response = [ 1 for _ in range(len(list))]

    list_url = find_element(list, regexp)#список всех url
    list_time = find_element(list, r"(:)(\d{1,2})(:)(\d{1,2}) ")

    for i in range(100  ):
        for j in range(i+1,len(list_url)):
            #4 строки не нужны. Просто для вывода
            print("\n\nThis is ---- i ", i," j - ", j)
            print(list_url[i].group(1), list_url[j].group(1))
            print("j - ", return_group(list_time[j], 2), return_group(list_time[j], 4))
            print("i - ", return_group(list_time[i], 2), return_group(list_time[i], 4))

            if find_time(list_time[i], list_time[j]):#обязательно 2 if
                if list_url[i].group(1) == list_url[j].group(1):#считаем количество одинаковых
                    response[i]+=1

            else:
                break

    return response



def write(filename, data, format='w'):
    with open(filename,format) as file:
        for i in range(len(data)):
            a = str(data[i]) + "\n\n"
            file.write(a)

if __name__=="__main__":
    file = reader("access_small.log")

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


    #поиск dos атак
    #regexp_dos_file = r"/[\S]{0,1000} HTTP/\d.\d"
    regexp_dos_file = r" (/.*) (HTTP/\d.\d)"
    status_dos = find_dos(file, regexp_dos_file)
    for i in range(len(status_dos)):
        if status_dos[i]>=10:
            write("dos.txt", status_dos)
            print(i, status_dos[i], file[i])











