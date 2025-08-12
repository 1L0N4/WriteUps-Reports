---
tags:
  - wireshark
  - kerberos
  - asreproasting
  - nmap
  - AD
  - RC4
creation date: 2025-08-01
content:
  - "[[#Задание]]"
  - "[[#1. What ports did the threat actor initially find open?]]"
  - "[[#2. The threat actor found four valid usernames, but only one username allowed the attacker to achieve a foothold on the server. What was the username?]]"
  - "[[#3. The threat actor captured a hash from the user in question 2. What are the last 30 characters of that hash?]]"
  - "[[#4. What is the user's password?]]"
  - "[[#5. What were the second and third commands that the threat actor executed on the system?]]"
  - "[[#6. What is the flag?]]"
  - "[[#Ссылки]]"
---
### Задание

A small music company was recently hit by a threat actor.  
The company's Art Directory, Larry, claims to have discovered a random note on his Desktop.

Given that they are just starting, they did not have time to properly set up the appropriate tools for capturing artifacts. Their IT contact only set up Wireshark, which captured the events in question.

You are tasked with finding out how this attack unfolded and what the threat actor executed on the system.
### 1. What ports did the threat actor initially find open? 
По трафику видно, что атакующим производилось SYN сканирование жертвы утилитой nmap. Применим следующий фильтр в Wireshark: "tcp.flags == 0x012 && ip.src == 10.0.2.75 && frame.number < 2900". Здесь мы отфильтровываем пакеты по следующим признакам:
- установлены флаги на позициях 0000 0001 0010, то есть SYN+ACK
- отвечает именно жертва с ip адресом 10.0.2.75
-  порты были открыты на момент сканирования, а не позже.

![[Pasted image 20250729035442.png]]

![[Pasted image 20250812195707.png]]

Итак, на машине было открыто 13 портов: 53,80,[REDACTED],5357. Можем предположить, что жертва с большой долей вероятности - контроллер домена windows, как минимум с ролями DNS сервера, DHCP сервера и веб-сервера. Видим, что открыты порты LDAP для коммуникации вне домена (389(ldap),636(ldaps)) и для доступа к ресурсам внутри AD (3268(ldap),3269(ldaps)). IIS сервер слушает на порту 80.

Также запомним ip адреса атакующего 10.0.2.74 и жертвы 10.0.2.75, это поможет нам отфильтровать лишнее, так как Windows машины очень общительны. 

Тайминг nmap сканирования - **04:41:44-04:42:02 (UTC)**. Далее атакующий сканирует открытые порты повторно, чтобы узнать версию слушающих их сервисов **с 04:42:45 по 04:43:15**.

Сканирование закончено и в **04:43:24** злоумышленник заходит на сайт-визитную карточку компании со своего браузера:
![[Pasted image 20250812200658.png]]
Из дампа мы видим, что он получил информацию о возможных пользователях домена благодаря контактной информации на сайте.

### 2. The threat actor found four valid usernames, but only one username allowed the attacker to achieve a foothold on the server. What was the username?

Составив список юзернеймов, в **04:43:52** атакующий провел энумерацию пользователей по протоколу керберос в домене DIRECTORY.THM, возможно с помощью скрипта GetNPUsers.py или утилиты kerbrute:
![[Pasted image 20250812202541.png]]

Он нашел существующие юзернеймы в домене:
- john.doe
- larry.doe
- ranith.kays
- joаn.ray

В данном случае нас интересовали любые ответы kerberos на AS-REQ (Request to Authentication Service) кроме PRINCIPAL_UNKNOWN.

Судя по всему у пользователя [REDACTED] отключена пре-аутентификация kerberos и злоумышленник таким образом может получить валидный kerberos билет и NT хэш. Эта атака называется ASREProasting
![[Pasted image 20250812203124.png]]

Ранее при обычном запросе к KDC (Key Distribution Center) сессионный ключ и билет TGT шифровались алгоритмом AES, как видим на скриншоте ниже (подчеркнуто голубым). KDC по умолчанию использует самое сложное шифрование из тех вариантов, что поддерживает ОС клиента. Но вот TGT, который использует только krbtgt, всегда шифруется самым надежным ключом, здесь это AES256. Зачастую поддерживаемые алгоритмы шифрования в AD выбираются группами, поэтому рядом с AES128 и AES256 вполне могут соседствовать менее надежные RC4 и DES, оставленные для совместимости со старым ПО.
![[Pasted image 20250812203322.png]]

Атакующий воспользовался этим и даунгрейднул алгоритм шифрования сессионного ключа до RC4, чтобы получить NTLM хэш юзера и забрутфорсить пароль:
![[Pasted image 20250812203741.png]]

Итак, в **04:45:17** атакующий подключается по WinRM к хосту жертвы от пользователя [REDACTED]
![[Pasted image 20250812204107.png]]
Ответ на второй вопрос - `[REDACTED]`

### 3. The threat actor captured a hash from the user in question 2. What are the last 30 characters of that hash?

Коммуникация  внутри сессии winRM зашифрована, чтобы ее прочитать нам также необходимо получить NTLM хэш. Один из способов - воспользоваться скриптом [[https://github.com/mlgualtieri/NTLMRawUnHide | NTLMRawUnHide.py]] Он читает предоставленные файлы побайтово и ищет сигнатуры NTLMSSP рукопожатия: NTLMSSP_NEGOTIATE --> NTLMSSP_CHALLENGE --> NTLMSSP_AUTH. Собрав из этих сообщений server challenge, ntml response и прочие необходимые данные, скрипт пытается восстановить хэш и печатает его в удобном для дальнейшего брутфорса формате, однако сами NTLMSSP сообщения перед этим должны быть предварительно декодированы из base64:

```shell
V:\CTFs\THM>python NTLMRawUnHide.py -i ntml_handshake1.raw -q
←[1;37mSearching ntml_handshake1.raw for NTLMv2 hashes...
←[0;97m
[REDACTED(username)]:::ec89ba38b848e655:f6dd396748ca42ed9b5c4dedf23aeec0:010100000000000000d30f891250da01e3cd78db2e80fd3900000000020012004400490052004500430054004f0052005900010010004100440053004500520056004500520004001a006400690072006500630074006f00720079002e00740068006d0003002c00410044005300650072007600650072002e006400690072006500630074006f00720079002e00740068006d0005001a006400690072006500630074006f00720079002e00740068006d0007000800de2f87891250da010000000000000000


V:\CTFs\THM>python NTLMRawUnHide.py -i ntml_handshake2.raw -q
←[1;37mSearching ntml_handshake2.raw for NTLMv2 hashes...
←[0;97m
REDACTED(username)::directory.thm:4d466ef19179c690:e18eca5d5ed8a7a08682a3cd4e993b3e:01010000000000008212cb751250da01fc1010028b6c723900000000020012004400490052004500430054004f0052005900010010004100440053004500520056004500520004001a006400690072006500630074006f00720079002e00740068006d0003002c00410044005300650072007600650072002e006400690072006500630074006f00720079002e00740068006d0005001a006400690072006500630074006f00720079002e00740068006d00070008008212cb751250da0109001e00570053004d0041004e002f00310030002e0030002e0032002e003700350006000400020000000000000000000000
```

Пример того, как выглядит полное ntlmssp рукопожатие:
![[Pasted image 20250803070637.png]]
Второй способ получения хэшей из дампа трафика - использование скрипта [[https://github.com/openwall/john/blob/bleeding-jumbo/run/krb2john.py|krb2john.py]]. Сохраним трафик в подходящий для скрипта формат и запустим его:
`tshark -r traffic-1725627206938.pcap -T pdml > data.pdml`
`python3 krb2john.py data.pdml`

Скрипт ищет и извлекает AS-REP и TGS-REP хэши в удобный для брутфорса формат:
`$krb5asrep$23$f8716efbaa984508ddde606756441480$805ab8be8cfb018a282718f7c040cd43924c6f9afeb6171230bbd3dccc79294dcf2f877a44c1a0981aadb7bb7a9510dd52d8dda4039ef4dcb444f18c9902be1623035e10aebf16ce4bdf5f7064f480e67e96ec2eb32bad95c5a1247bd7a241273fe80e281f4e6a99926f7969fcf803190c7096b947a33407f8578d4c0fb8b52d2aa8d0405a44b72bd21e014563cb71e82aee0e12538d0d440c930b98abf766e18ddc99a964e6e812ecf8dc8994a912a02074d40e5e6906915c1d216653d45df88636b51656f2c37de2020a2fd86ee7ecf6f0afe3f509fd31144e1573f9587155...9f`

Последние 30 символов хэша - ответ на 3 вопрос - `55[REDACTED]9f`
### 4. What is the user's password?

Теперь мы можем получить пароль:

```shell
hashcat.exe -a 0 -m 5600 hash3.txt rockyou.txt

[REDACTED(username)]::directory.thm:4d466ef19179c690:e18eca5d5ed8a7a08682a3cd4e993b3e:01010000000000008212cb751250da01fc1010028b6c723900000000020012004400490052004500430054004f0052005900010010004100440053004500520056004500520004001a006400690072006500630074006f00720079002e00740068006d0003002c00410044005300650072007600650072002e006400690072006500630074006f00720079002e00740068006d0005001a006400690072006500630074006f00720079002e00740068006d00070008008212cb751250da0109001e00570053004d0041004e002f00310030002e0030002e0032002e003700350006000400020000000000000000000000:[REDACTED(password)]

[REDACTED(username)]:::ec89ba38b848e655:f6dd396748ca42ed9b5c4dedf23aeec0:010100000000000000d30f891250da01e3cd78db2e80fd3900000000020012004400490052004500430054004f0052005900010010004100440053004500520056004500520004001a006400690072006500630074006f00720079002e00740068006d0003002c00410044005300650072007600650072002e006400690072006500630074006f00720079002e00740068006d0005001a006400690072006500630074006f00720079002e00740068006d0007000800de2f87891250da010000000000000000:[REDACTED(password)]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: hash3.txt
Time.Started.....: Tue Jul 29 11:35:57 2025 (0 secs)
Time.Estimated...: Tue Jul 29 11:35:57 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 92241.7 kH/s (8.18ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new), 2/2 (100.00%) Salts
Progress.........: 3145728/28688768 (10.97%)
Rejected.........: 0/3145728 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> lindarockyou
Hardware.Mon.#1..: Temp: 42c Fan:  0% Util: 34% Core:2010MHz Mem:5750MHz Bus:16

Started: Tue Jul 29 11:35:48 2025
Stopped: Tue Jul 29 11:35:58 2025
```

Таким образом, пароль и ответ на вопрос 4 - [REDACTED] 

Введя его в поле NT Password, мы расшифруем часть коммуникации по WinRM
![[Pasted image 20250812205328.png]]

Также мы можем получить хэш функцию NT пароля и добавить ее в файл keytab.kt в wireshark, результат будет тем же:
```shell
┌──(kali㉿user)-[~/Desktop/pyCryptoDome]
└─$ cat hash.py 
import hashlib

password = '[REDACTED]'

nt_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
print(nt_hash.hex())

┌──(kali㉿user)-[~/Desktop/pyCryptoDome]
└─$ python3 hash.py 
7f[REDACTED]4f
```
```python
from struct import unpack, pack
from impacket.structure import Structure
import binascii
import sys

# Keytab structure from http://www.ioplex.com/utilities/keytab.txt
  # keytab {
  #     uint16_t file_format_version;                    /* 0x502 */
  #     keytab_entry entries[*];
  # };

  # keytab_entry {
  #     int32_t size;
  #     uint16_t num_components;    /* sub 1 if version 0x501 */
  #     counted_octet_string realm;
  #     counted_octet_string components[num_components];
  #     uint32_t name_type;   /* not present if version 0x501 */
  #     uint32_t timestamp;
  #     uint8_t vno8;
  #     keyblock key;
  #     uint32_t vno; /* only present if >= 4 bytes left in entry */
  # };

  # counted_octet_string {
  #     uint16_t length;
  #     uint8_t data[length];
  # };

  # keyblock {
  #     uint16_t type;
  #     counted_octet_string;
  # };

class KeyTab(Structure):
    structure = (
        ('file_format_version','H=517'),
        ('keytab_entry', ':')
    )
    def fromString(self, data):
        self.entries = []
        Structure.fromString(self, data)
        data = self['keytab_entry']
        while len(data) != 0:
            ktentry = KeyTabEntry(data)

            data = data[len(ktentry.getData()):]
            self.entries.append(ktentry)

    def getData(self):
        self['keytab_entry'] = b''.join([entry.getData() for entry in self.entries])
        data = Structure.getData(self)
        return data

class OctetString(Structure):
    structure = (
        ('len', '>H-value'),
        ('value', ':')
    )

class KeyTabContentRest(Structure):
    structure = (
        ('name_type', '>I=1'),
        ('timestamp', '>I=0'),
        ('vno8', 'B=2'),
        ('keytype', '>H'),
        ('keylen', '>H-key'),
        ('key', ':')
    )

class KeyTabContent(Structure):
    structure = (
        ('num_components', '>h'),
        ('realmlen', '>h-realm'),
        ('realm', ':'),
        ('components', ':'),
        ('restdata',':')
    )
    def fromString(self, data):
        self.components = []
        Structure.fromString(self, data)
        data = self['components']
        for i in range(self['num_components']):
            ktentry = OctetString(data)

            data = data[ktentry['len']+2:]
            self.components.append(ktentry)
        self.restfields = KeyTabContentRest(data)

    def getData(self):
        self['num_components'] = len(self.components)
        # We modify the data field to be able to use the
        # parent class parsing
        self['components'] = b''.join([component.getData() for component in self.components])
        self['restdata'] = self.restfields.getData()
        data = Structure.getData(self)
        return data

class KeyTabEntry(Structure):
    structure = (
        ('size','>I-content'),
        ('content',':', KeyTabContent)
    )

# Add your own keys here!
# Keys are tuples in the form (keytype, 'hexencodedkey')
# Common keytypes for Windows:
# 23: RC4
# 18: AES-256
# 17: AES-128
# Wireshark takes any number of keys in the keytab, so feel free to add
# krbtgt keys, service keys, trust keys etc
keys = [
    (23, '7f[REDACTED]4f'),
]
nkt = KeyTab()
nkt.entries = []

for key in keys:
    ktcr = KeyTabContentRest()
    ktcr['keytype'] = key[0]
    ktcr['key'] = binascii.unhexlify(key[1])
    nktcontent = KeyTabContent()
    nktcontent.restfields = ktcr
    # The realm here doesn't matter for wireshark but does of course for a real keytab
    nktcontent['realm'] = b'DIRECTORY.THM'
    krbtgt = OctetString()
    krbtgt['value'] = 'krbtgt'
    nktcontent.components = [krbtgt]
    nktentry = KeyTabEntry()
    nktentry['content'] = nktcontent
    nkt.entries.append(nktentry)

data = nkt.getData()
if len(sys.argv) < 2:
    print('Usage: keytab.py <outputfile>')
    print('Keys should be written to the source manually')
else:
    with open(sys.argv[1], 'wb') as outfile:
        outfile.write(data)
```
```shell
┌──(kali㉿user)-[~/Desktop]
└─$ python3 keytab.py keytab.kt

┌──(kali㉿user)-[~/Desktop]
└─$ xxd keytab.kt 
00000000: 0502 0000 0036 0001 000d 4449 5245 4354  .....6....DIRECT
00000010: 4f52 592e 5448 4d00 066b 7262 7467 7400  ORY.THM..krbtgt.
00000020: 0000 0100 0000 0002 0017 0010 7fac dc49  ...............I
00000030: 8ed1 680c 4fd1 4483 19a8 c04f            ..h.O.D....O
```

![[Pasted image 20250812205824.png]]
![[Pasted image 20250812205953.png]]
### 5. What were the second and third commands that the threat actor executed on the system?

Декодируем base64 из поля Decrypted data и получаем список команд, введенных злоумышленником:

![[Pasted image 20250801102049.png]]
```powershell
whoami /all
[REDACTED]
[REDACTED]
reg save HKLM\SECURITY C:\SECURITY
(get-item 'C:\SAM').length
```

Вторая и третья команды будут являться ответами на 5 вопрос.
Узнать какие именно данные в сессии WinRM относятся к командам можно пролистав дамп и обратив внимание на xml разметку, а именно на такие тэги как `<rsp:CommandLine> и <rsp:Arguments>` или по размеру поля data. Введем фильтр `http.request.method == "POST" && data.len > 8000 && data.len < 11000` и получим всего 36 пакетов. 

![[Pasted image 20250812210259.png]]
### 6. What is the flag?

Однако, после нескольких успешно расшифрованных пакетов в поле decrypted data появляется мусор вместо читаемых ASCII-символов и пока что флаг мы не видим. Почему так? Никаких признаков того, что сессия прерывалась или менялись ключи шифрования нет. Ответ кроется в типа шифра RC4 - он потоковый и синхронизируется с ключом по счётчику байтов. При ошибке в подсчете одного байта поток рассинхронизируется. Посмотрим на последний успешно расшифрованный фрейм №5356:
![[Pasted image 20250812210834.png]]

Видим, что отсутствует закрывающая скобка для тэга, при этом размер расшифрованных данных равен 9495 байт, а размер данных WinRM, указанный в заголовке, 9496 байт. Заметим также нетипичный символ возврата каретки `\r` на месте где должен быть байт закрывающей скобки. Теперь все ясно: вместо того, чтобы расшифровать 0x0d Wireshark интерпретировал его как обозначение конца зашифрованных данных. Такая же ситуация повторилась в нескольких последующих фреймах: 5361, 5700, 8393, 8875, 8883, 9383 и 9469. Пакетов немного, поэтому изменим символы новой строки и возврата каретки на любые другие вручную в hex редакторе. Какие именно - не принципиально, главное - восстановить поток.
![[Pasted image 20250802222354.png]]

После этого нам доступны для декодирования из base64 все остальные команды, которые вводил атакующий на скомпрометированной машине:

```powershell
(get-item 'C:\SYSTEM').length
cd ..\Desktop\
echo "THM{REDACTED}" &gt; note.txt
```

### Ссылки:
- https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797
- https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7
- https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol
