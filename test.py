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

def Sravnivanie(resultold, resultnew): #сравниваем два сканирования и вывести различия
    razlichie = list(set(resultnew) - set(resultold))
    return razlichie

def Port():
    nmap = nmap3.Nmap()
    port = "-p "
    port += str(80)
    result = nmap.scan_command("46.235.184.240", arg = port)
    # resultclean = re.findall('\'protocol\'', str(result))
    # set(resultclean)
    # print(set(resultclean))
    print(result)                   

#реализация функций
resultold = VivodIzFailaOld()
print(Fore.BLUE + str(resultold)) #вывод в консоль
resultnew = VivodIzFailaNew()
print(Fore.YELLOW + str(resultnew)) #вывод в файл
razlichie = Sravnivanie(set(resultold), set(resultnew))
print(Fore.GREEN + str(razlichie)) #вывод в файл
print(Fore.WHITE)
Port()
