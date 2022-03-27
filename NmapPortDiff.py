import nmap #импорт библиотеки программы Nmap
import pickle #импорт вывода в/из файла
import dictdiffer #импорт сравнивания словарей

def FirstScan():
    result = Scan() #сканирование портов диапазона адресов Гринатома
    with open('resultold.txt','wb') as file: #вывод в файл
        pickle.dump(result, file)

def SecondScan():
    result = Scan() #сканирование портов диапазона адресов Гринатома
    with open('resultnew.txt','wb') as file: #вывод в файл
        pickle.dump(result, file)

def FileInputOld():
    with open('resultold.txt','rb') as file:
        content = pickle.load(file) #вывод из файла
    return content #формирование списка из результата вывода

def FileInputNew():
    with open('resultnew.txt','rb') as file:
        content = pickle.load(file) #вывод из файла
    return content #формирование списка из результата вывода

def Difference(resultold, resultnew): #сравниваем два сканирования и выводим различия
    for diff in list(dictdiffer.diff(resultold, resultnew)):
        print(diff)
        print("-----------------------------------------------------------------------------------")


def Scan():
    nm = nmap.PortScanner()
    nm.scan(hosts='93.187.72.0-255', arguments='-n -p 80,443') #сканирование портов диапазона адресов Гринатома
    ports = list()
    result = dict()
    '''
    Выборка нужного из результатов сканирования и запись этого
    в виде словаря (если поэтапно, то в переменную типа list 
    записываются значения протокола, номера порта и его состояния,
    а потом это всё присвивается в словаре нужному IP-адресу)
    '''
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                ports = "'protocol': '"+str(proto)+"', 'port': '"+str(port)+"', 'state': '"+str(nm[host][proto][port]['state']+"'")
                result.setdefault(host, []).append(ports)         
    return result

#реализация функций
resultold = FileInputOld()
resultnew = FileInputNew()
difference = Difference(resultold, resultnew)

