import nmap3 #импорт библиотеки программы Nmap
import re #импорт регулярных выражений
import pickle #импорт вывода в/из файла
from colorama import init, Fore #цвет вывода

def PervoeScanirovanie():
    nmap = nmap3.NmapScanTechniques() 
    result = nmap.nmap_ping_scan("93.187.72.0-255") #сканирование диапазона адресов Гринатома
    resultclean = re.findall('\d{2}\.\d{3}\.\d{2}\.\d{1,3}', str(result)) #очистка вывода от мусора, остаются только айпи адреса
    set(resultclean) #формирование списка из результата
    with open('resultcleanold.txt','wb') as file: #вывод в файл
        pickle.dump(resultclean, file)

def DrugoeScanirovanie():
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_ping_scan("93.187.72.0-255") #второе сканирование диапазона адресов Гринатома
    resultclean = re.findall('\d{2}\.\d{3}\.\d{2}\.\d{1,3}', str(result)) #очистка вывода от мусора, остаются только айпи адреса
    set(resultclean) #формирование списка из результата
    with open('resultcleannew.txt','wb') as file: #вывод в файл
        pickle.dump(resultclean, file)

def VivodIzFailaOld():
    with open('resultcleanold.txt','rb') as file:
        content = pickle.load(file) #вывод из файла
    return set(content) #формирование списка из результата вывода

def VivodIzFailaNew():
    with open('resultcleannew.txt','rb') as file:
        content = pickle.load(file) #вывод из файла
    return set(content) #формирование списка из результата вывода

def Sravnivanie(resultold, resultnew): #сравниваем два сканирования и выводим различия
    razlichie = list(set(resultnew) - set(resultold))
    return razlichie

def ScanPorts():
    nmap = nmap3.Nmap()
    attribute = "-p " #атрибут команды скана портов для nmap
    port = input("Введите порты(через запятую или диапазоном)\n")
    attribute += str(port) #добавление портов к атрибуту которые будут сканироваться
    
    #46.235.184.240
    ipport = dict()
    IPrange = ['93.187.72.82', '93.187.72.94', '93.187.72.115', '93.187.72.241', '93.187.72.19', '93.187.72.59', '93.187.72.208', 
    '93.187.72.179', '93.187.72.24', '93.187.72.137', '93.187.72.136', '93.187.72.130']
    for ip in IPrange: #создается переменная ip которая берет из списка по одному адресу и сканирует его порты
        result = ""
        result = nmap.scan_command(ip, arg = attribute) #команда которая передается в Nmap с атрибутом для сканирования портов
        print(result)
        # самим списком портов и айпи адресом который сканируется
        resultclean = ""
        #очистка вывода чтобы осталось только состояние портов
        resultclean = re.findall('\'protocol\': \'\w+\', \'portid\': \'\w+\', \'state\': \'\w+\'', str(result))
        for res in resultclean:
            ipport.setdefault(ip, []).append(res) #запись отсканированных портов в словарь ip адресов
    print(ipport)

#реализация функций
resultold = VivodIzFailaOld()
print(Fore.BLUE + str(resultold)) #вывод в консоль
resultnew = VivodIzFailaNew()
print(Fore.YELLOW + str(resultnew)) #вывод в консоль
razlichie = Sravnivanie(set(resultold), set(resultnew))
print(Fore.GREEN + str(razlichie)) #вывод в консоль
print(Fore.WHITE)
print(nmap3.__file__)
