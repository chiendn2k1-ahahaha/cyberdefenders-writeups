title: Zerologon
summary: Truy vết chuỗi tấn công từ một máy trạm phòng tài chính tới Domain Controller qua Sysmon, Security, System log và USN Journal.

# Zerologon

- **Lab:** [Zerologon](https://cyberdefenders.org/blueteam-ctf-challenges/zerologon/) trên CyberDefenders. Nhóm Endpoint Forensics, độ khó Hard, đã retired.
- **Dữ liệu:** bộ thu thập KAPE của 4 máy trong domain `elitesystems.local`: `DC01`, `FileServer`, `FIN-PC`, `IT-PC`.
  - Event log: Sysmon Operational, Security, System.
  - NTFS: `$Extend\$J` (USN Journal).
  - Thư mục người dùng (`Users\...\AppData\Local\Temp`).
- **Công cụ trong VM của lab:** PowerShell `Get-WinEvent` (lọc XPath ngay trên file EVTX) và `MFTECmd` (Zimmerman Tools) để đọc USN Journal.
- **Quy ước:**
  - Giờ trong log là UTC. Bài ghi dạng `UTC (UTC+7)`.
  - <span class="red">Khung đỏ</span> trên ảnh là chỗ cần chú ý.
  - Vùng làm mờ là giá trị trùng với đáp án của câu hỏi trong lab.

## Tóm tắt kết quả

- `FIN-PC` (user `esmith`) chạy file `easygoing.exe` trong thư mục Temp. File này kết nối ra một IP bên ngoài qua TCP/80 và sinh ra các tiến trình con thực hiện recon, PowerShell mã hóa Base64 và tải script từ một listener cục bộ.
- Trên `DC01`, mật khẩu tài khoản máy `DC01$` bị đổi bởi `ANONYMOUS LOGON` lúc 20:15:38 UTC (03:15:38 UTC+7 ngày 03/01/2024). Đây là dấu hiệu đặc trưng khi khai thác CVE-2020-1472 (Zerologon).
- Sau thời điểm đó, tài khoản domain `dlee` đăng nhập vào `DC01` từ chính IP mà `easygoing.exe` kết nối tới. Tài khoản này chạy lệnh qua WMI để tắt Microsoft Defender và mở RDP.
- Kẻ tấn công cài service tên ngẫu nhiên qua share `ADMIN$` trên cả 4 máy. Sau đó có các hành vi:
  - truy cập bộ nhớ `lsass.exe`;
  - leo quyền qua named pipe;
  - dùng thông tin đăng nhập của tài khoản `FileShareService` để chạy lệnh từ xa;
  - tạo scheduled task để duy trì truy cập (persistence);
  - cài phần mềm điều khiển từ xa trên `FileServer`.
- Cuối chuỗi, script `localdisk.ps1` chạy trên cả 4 máy. Script nén từng thư mục người dùng thành file zip trong `C:\Data`.
- **Chưa đủ dữ liệu để kết luận** dữ liệu đã bị đưa ra ngoài (exfiltration).

## Chuẩn bị truy vấn

- Mở PowerShell trong VM, trỏ biến `$A` tới thư mục artifact.
- Hai hàm dưới đây đọc trực tiếp file EVTX của từng máy và chuyển mỗi sự kiện thành object có tên trường (UtcTime, Image, CommandLine...).
- VM phân tích không cài Sysmon, nên trường `Message` bị trống. Phải lọc bằng XPath trên `EventData` thay vì tìm chữ trong Message.

```powershell
$A = "$home\desktop\start here\artifacts"
function ev($h,$log,$xp,$max=20000){ Get-WinEvent -Path "$A\$h\Windows\System32\winevt\logs\$log.evtx" -FilterXPath $xp -MaxEvents $max -ea 0 }
function sx($e){ $x=[xml]$e.ToXml(); $o=[ordered]@{UtcTime=$e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss');Computer=$e.MachineName}
  $x.Event.EventData.Data | ?{$_.Name} | %{ $o[$_.Name]=$_.'#text' }; [pscustomobject]$o }
# sq <máy> <loại sự kiện Sysmon> <tên trường> <giá trị> [số bản ghi]
function sq($h,$id,$f,$v,$n=5){ ev $h 'Microsoft-Windows-Sysmon%4Operational' "*[System[EventID=$id]] and *[EventData[Data[@Name='$f']='$v']]" $n | %{ sx $_ } }
```

- Trong các lệnh bên dưới, tham số thứ hai của `sq` là loại sự kiện Sysmon: `1` là tạo tiến trình (process creation), `3` là kết nối mạng, `10` là truy cập tiến trình khác (process access), `11` là tạo file.

## Bước 1: tìm tiến trình lạ trên FIN-PC

- **Mục tiêu:** tìm tiến trình chạy từ thư mục người dùng, không phải từ `Program Files` hay `System32`.
- **Cách làm:**
  - Liệt kê sự kiện Sysmon tạo tiến trình trên cả 4 máy.
  - Bỏ các tiến trình hệ thống quen thuộc (svchost, Defender, VMware Tools, Edge Update...).
  - Gom theo tiến trình cha (ParentImage).
- **Kết quả:** `C:\Users\esmith\AppData\Local\Temp\easygoing.exe` là tiến trình cha của nhiều lệnh cmd, PowerShell và một binary hệ thống.

<figure><img src="../img/zerologon/zl-01-easygoing-child.png" alt="Sysmon FIN-PC: tiến trình con của easygoing.exe"><figcaption>Sysmon Operational của FIN-PC, sự kiện tạo tiến trình. Hai tiến trình con của easygoing.exe: một chạy bằng tài khoản FIN-PC\Administrator (20:44:53 UTC), một là PowerShell có -EncodedCommand chạy bằng ELITESYSTEMS\esmith (20:09:37 UTC).</figcaption></figure>

- **Nhận định:**
  - Một file thực thi trong `AppData\Local\Temp` sinh ra PowerShell với `-nop -exec bypass -EncodedCommand` là hành vi bất thường.
  - Cùng một tiến trình cha chạy được bằng hai tài khoản khác nhau (`esmith` rồi `FIN-PC\Administrator`). Điều này cho thấy quyền đã thay đổi trong khoảng 20:09 đến 20:44 UTC.

## Bước 2: xác định máy chủ điều khiển (C2)

- **Mục tiêu:** xem `easygoing.exe` kết nối đi đâu.
- **Cách làm:** lọc sự kiện Sysmon kết nối mạng có `Image` đúng bằng đường dẫn của `easygoing.exe`.

```powershell
sq FIN-PC 3 Image C:\Users\esmith\AppData\Local\Temp\easygoing.exe 2 | fl UtcTime,User,Image,Protocol,SourceIp,DestinationIp,DestinationPort
```

<figure><img src="../img/zerologon/zl-02-easygoing-c2.png" alt="Sysmon FIN-PC: kết nối mạng của easygoing.exe"><figcaption>Sysmon Operational của FIN-PC, sự kiện kết nối mạng. easygoing.exe (user esmith) kết nối TCP tới một IP public qua cổng 80 lúc 11:11:37 và 11:12:07 UTC.</figcaption></figure>

- **Nhận định:**
  - Đích là một IP public, giao thức TCP, cổng 80. IP này xuất hiện lại ở Bước 5 (đăng nhập vào DC01), nên có thể coi là hạ tầng của kẻ tấn công.
  - Giờ kết nối (11:11 UTC) sớm hơn giờ các tiến trình con (từ 19:44 UTC). Log có sẵn chưa giải thích được khoảng chênh này.

## Bước 3: giải mã PowerShell và recon Active Directory

- **Mục tiêu:** đọc nội dung các lệnh PowerShell mã hóa do `easygoing.exe` chạy.
- **Cách làm:** lấy tham số cuối của CommandLine rồi giải mã Base64 theo UTF-16LE.

```powershell
sq FIN-PC 1 ParentImage C:\Users\esmith\AppData\Local\Temp\easygoing.exe 60 | ?{$_.CommandLine -match 'EncodedCommand'} | sort UtcTime |
  %{ '{0}  {1}' -f $_.UtcTime, [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($_.CommandLine -split ' ')[-1])) }
```

<figure><img src="../img/zerologon/zl-10-decoded-powershell.png" alt="Nội dung PowerShell sau khi giải mã"><figcaption>Kết quả giải mã. Lệnh lúc 19:50:32 UTC (đã làm mờ) là lệnh truy vấn Active Directory và xuất ra CSV trong Temp. Lệnh lúc 20:09:37 UTC tải script từ http://127.0.0.1:25816/ rồi chạy Invoke-ShareFinder và ghi kết quả ra found_shares.txt.</figcaption></figure>

- **Nhận định:**
  - Lệnh thứ nhất dùng module Active Directory để liệt kê toàn bộ computer object trong domain và xuất ra file CSV.
  - Lệnh thứ hai tải script qua một listener trên `127.0.0.1` rồi gọi `Invoke-ShareFinder` (một hàm của PowerView) để dò share có quyền truy cập. Cách nạp script qua cổng cục bộ thường gặp ở các framework C2 có chức năng PowerShell import.
  - Hướng giải: câu hỏi về lệnh recon nằm ở dòng đã làm mờ.

## Bước 4: dấu hiệu khai thác Zerologon trên DC01

- **Mục tiêu:** kiểm tra tài khoản máy của Domain Controller có bị đổi mật khẩu bất thường không.
- **Cách làm:** đọc Security log của `DC01`, lọc sự kiện thay đổi tài khoản máy (computer account changed).

```powershell
ev DC01 Security '*[System[EventID=4742]]' 20 | %{ sx $_ } | ft UtcTime,SubjectUserName,TargetUserName,PasswordLastSet,IpAddress -wrap
```

<figure><img src="../img/zerologon/zl-07-dc01-zerologon-4742.png" alt="Security DC01: DC01$ bị đổi mật khẩu bởi ANONYMOUS LOGON"><figcaption>Security log của DC01. Lúc 20:15:38 UTC, tài khoản DC01$ được cập nhật mật khẩu (PasswordLastSet) với người thực hiện là ANONYMOUS LOGON. Hai bản ghi lúc 20:29:35 UTC do chính DC01$ thực hiện.</figcaption></figure>

- **Nhận định:**
  - Bình thường, tài khoản máy tự đổi mật khẩu bằng chính nó (Subject là `DC01$`), như hai dòng lúc 20:29:35 UTC.
  - Mật khẩu được đặt bởi `ANONYMOUS LOGON` khớp với kỹ thuật Zerologon: lợi dụng lỗi Netlogon (CVE-2020-1472) để đặt lại mật khẩu tài khoản máy của DC mà không cần xác thực.
  - Cột `PasswordLastSet` hiển thị theo múi giờ của VM phân tích (12:15:38 PM, UTC-8), tương ứng 20:15:38 UTC.
  - **Chưa đủ dữ liệu** để xác định IP gửi yêu cầu Netlogon: trường IpAddress trống, và Sysmon của DC01 không có kết nối mạng nào của `lsass.exe` trong khoảng 20:13 đến 20:16 UTC.

## Bước 5: tài khoản dlee điều khiển DC01 qua WMI

- **Mục tiêu:** xem ai chạy lệnh trên DC01 ngay sau khi mật khẩu `DC01$` bị đổi.
- **Cách làm:** lọc tiến trình có cha là `WmiPrvSE.exe` trên DC01.

```powershell
sq DC01 1 ParentImage C:\Windows\System32\wbem\WmiPrvSE.exe 30 | sort UtcTime |
  ft @{n='UtcTime';e={$_.UtcTime.Substring(11,8)}},User,@{n='Cmd';e={$_.CommandLine -replace ' 1> .*',''}} -wrap
```

<figure><img src="../img/zerologon/zl-04-dc01-wmi-commands.png" alt="Sysmon DC01: lệnh chạy qua WMI bằng tài khoản dlee"><figcaption>Sysmon Operational của DC01. Từ 20:22:26 đến 20:29:50 UTC, ELITESYSTEMS\dlee chạy các lệnh cmd.exe /Q /c qua WMI: whoami, thêm policy tắt Defender, đổi kiểu khởi động service WinDefend thành disabled, sửa registry Terminal Server (đã làm mờ) và mở firewall cho remoteadmin, remotedesktop.</figcaption></figure>

- **Nhận định:**
  - Mẫu lệnh `cmd.exe /Q /c <lệnh> 1> \\127.0.0.1\ADMIN$\__<số>` (phần sau `1>` đã được cắt bớt khi hiển thị) giống cách công cụ wmiexec của Impacket ghi kết quả lệnh ra share `ADMIN$`.
  - Thứ tự lệnh cho thấy kẻ tấn công tắt Microsoft Defender trước, sau đó bật RDP và mở firewall.
  - Hướng giải: câu hỏi về lệnh bật RDP nằm ở dòng 20:29:34 đã làm mờ.
- **Kiểm tra thêm:** `dlee` đăng nhập vào DC01 từ đâu? Lọc Security log của DC01, lấy các phiên đăng nhập thành công của `dlee` có IP nguồn, gom theo IP, kiểu đăng nhập và giao thức xác thực.

```powershell
ev DC01 Security "*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName']='dlee']]" 300 | %{ sx $_ } |
  ?{ $_.IpAddress -notin '-','::1','127.0.0.1' } | group IpAddress,LogonType,AuthenticationPackageName |
  %{ $t = $_.Group.UtcTime | sort; [pscustomobject]@{ Count=$_.Count; Key=$_.Name; First=$t[0]; Last=$t[-1] } } | ft -auto
```

<figure><img src="../img/zerologon/zl-11-dc01-dlee-logons.png" alt="Security DC01: đăng nhập của dlee"><figcaption>Security log của DC01. dlee có 56 lần đăng nhập qua mạng (LogonType 3, NTLM) từ 20:22:26 đến 22:02:28 UTC và 2 lần đăng nhập RDP (LogonType 10) lúc 20:30:57 UTC, tất cả từ cùng một IP (đã làm mờ). Đây là IP đích của easygoing.exe ở Bước 2.</figcaption></figure>

- **Nhận định:**
  - Phiên đăng nhập mạng đầu tiên (20:22:26 UTC) trùng giây với lệnh WMI đầu tiên.
  - Phiên RDP (20:30:57 UTC) diễn ra khoảng 1 phút sau khi RDP được bật (20:29:34 UTC).
  - Kẻ tấn công dùng `dlee` từ IP bên ngoài, không phải từ một máy trong mạng.
  - **Chưa đủ dữ liệu** để biết kẻ tấn công lấy thông tin đăng nhập của `dlee` bằng cách nào.
    - Sysmon của DC01 chỉ ghi nhận Sysmon64.exe truy cập `lsass.exe` (Bước 7).
    - Cần thêm: Security log của DC01 có bật audit "Directory Service Access" để thấy yêu cầu replication (DCSync), và packet capture DRSUAPI tại DC.

## Bước 6: lateral movement bằng service qua ADMIN$

- **Mục tiêu:** kiểm tra service mới được cài trên các máy.
- **Cách làm:** đọc System log của 4 máy, lọc sự kiện cài service mới (service installed).

```powershell
'DC01','FileServer','FIN-PC','IT-PC' | %{ $h=$_; ev $h System '*[System[EventID=7045]]' 9 | %{ sx $_ } |
  select @{n='Host';e={$h}},UtcTime,ServiceName,ImagePath } | ft -wrap
```

<figure><img src="../img/zerologon/zl-05-services.png" alt="System log: service tên ngẫu nhiên trên cả 4 máy"><figcaption>System log của 4 máy. Từ 20:53:52 đến 21:13:06 UTC, mỗi máy có một service tên 7 ký tự hex, ImagePath trỏ tới \\&lt;máy&gt;\ADMIN$\&lt;tên&gt;.exe. FileServer có thêm một service của phần mềm điều khiển từ xa lúc 21:18:51 UTC. Tên service trên FileServer đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Service tên ngẫu nhiên với file thực thi đặt thẳng trong `ADMIN$` (tức `C:\Windows`) là mẫu thực thi từ xa kiểu PsExec. Nhiều framework C2 dùng cách này để di chuyển ngang (lateral movement).
  - Thứ tự xuất hiện: `FIN-PC` (20:53 UTC), `IT-PC` (21:07), `FileServer` (21:09), `DC01` (21:13).

## Bước 7: truy cập LSASS và leo quyền

- **Mục tiêu:** tìm tiến trình đọc bộ nhớ `lsass.exe`, nơi Windows giữ thông tin đăng nhập.
- **Cách làm:** lọc sự kiện Sysmon truy cập tiến trình (process access) có đích là `lsass.exe`, bỏ các tiến trình bảo mật và hệ thống thường gặp.

```powershell
'FIN-PC','FileServer','DC01','IT-PC' | %{ sq $_ 10 TargetImage C:\Windows\system32\lsass.exe 400 |
  ?{$_.SourceImage -notmatch 'MsMpEng|svchost|wmiprvse|csrss|wininit|vmtoolsd|services'} | select -first 2 } |
  ft Computer,UtcTime,SourceImage,GrantedAccess -wrap
```

<figure><img src="../img/zerologon/zl-06-lsass-access.png" alt="Sysmon: tiến trình truy cập lsass.exe"><figcaption>Sysmon của 4 máy. Ngoài Sysmon64.exe (hành vi bình thường của chính Sysmon), cùng một binary hệ thống (đã làm mờ) mở handle tới lsass.exe trên FIN-PC (20:53:28 và 21:12:44 UTC), FileServer (21:11:01) và IT-PC (21:10:54).</figcaption></figure>

<figure><img src="../img/zerologon/zl-03-system-commands.png" alt="Sysmon FIN-PC: lệnh chạy dưới quyền SYSTEM"><figcaption>Sysmon của FIN-PC, các lệnh chạy dưới quyền NT AUTHORITY\SYSTEM: ghi dữ liệu vào một named pipe (21:12:44 UTC), WMIC tới 192.168.202.126 bằng tài khoản FileShareService kèm mật khẩu trong command line (21:28:43), và tạo scheduled task chạy PowerShell khi đăng nhập với quyền System (21:35:06). Các giá trị là đáp án đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Tiến trình truy cập `lsass.exe` trên 3 máy trong vòng khoảng 20 phút. Thời điểm này trùng với lúc service lạ được cài (Bước 6).
  - Lệnh `echo <chuỗi> > \\.\pipe\<số>` dưới quyền SYSTEM là mẫu leo quyền bằng named pipe impersonation, thường gặp ở lệnh `getsystem` của các framework C2.
  - Tài khoản `FileShareService` được dùng với mật khẩu ghi rõ trong command line. Đây là bằng chứng thông tin đăng nhập của tài khoản này đã bị lộ.
  - Scheduled task chạy một script PowerShell trong `AppData\Local` của `esmith` với quyền System khi có người đăng nhập là cơ chế persistence.
- **Kiểm tra thêm trên USN Journal của FIN-PC:** đọc `$Extend\$J` bằng MFTECmd, tìm bản ghi tạo file của các script liên quan.

```powershell
& MFTECmd.exe -f "$A\FIN-PC\$Extend\$J" --csv c:\w --csvf finpc_j.csv
import-csv c:\w\finpc_j.csv | ?{ $_.Name -in 'ChromeUpdate.ps1','localdisk.ps1' -and $_.UpdateReasons -eq 'FileCreate' }
```

<figure><img src="../img/zerologon/zl-13-usn-scripts.png" alt="USN Journal FIN-PC: tạo ChromeUpdate.ps1 và localdisk.ps1"><figcaption>USN Journal của FIN-PC: ChromeUpdate.ps1 được tạo lúc 17:16:29 UTC, localdisk.ps1 được tạo lúc 21:59:08 UTC.</figcaption></figure>

- **Nhận định:** script persistence được tạo khoảng 4 giờ trước khi scheduled task trỏ tới nó (21:35:06 UTC).

## Bước 8: phần mềm điều khiển từ xa trên FileServer

- **Cách làm:** lấy sự kiện Sysmon tạo tiến trình trên FileServer, giữ các lệnh có CommandLine chứa `--set-password`. XPath không hỗ trợ tìm chuỗi con, nên bước lọc này làm bằng PowerShell sau khi đọc log.

```powershell
ev FileServer 'Microsoft-Windows-Sysmon%4Operational' '*[System[EventID=1]]' 5000 | %{ sx $_ } |
  ?{ $_.CommandLine -match '--set-password' } | fl UtcTime,User,ParentImage,CommandLine
```

<figure><img src="../img/zerologon/zl-08-fileserver-remote-tool.png" alt="Sysmon FileServer: đặt mật khẩu cho phần mềm điều khiển từ xa"><figcaption>Sysmon của FileServer lúc 21:21:42 UTC: dưới quyền SYSTEM, tiến trình cha (đã làm mờ) chạy cmd để đặt mật khẩu truy cập không cần người dùng xác nhận cho phần mềm điều khiển từ xa vừa cài ở Bước 6. Mật khẩu và tên phần mềm đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Phần mềm điều khiển từ xa được cài dạng service, kèm mật khẩu truy cập cố định. Kẻ tấn công vẫn vào lại được kể cả khi C2 bị chặn.

## Bước 9: script gom dữ liệu localdisk.ps1

- **Mục tiêu:** xác định dữ liệu bị nhắm tới.
- **Cách làm:**
  - Tìm cùng một lệnh PowerShell mã hóa trên cả 4 máy, giải mã tham số Base64.
  - Bản sao của script nằm trong `Users\Administrator\AppData\Local\Temp` của từng máy trong bộ thu thập.

```powershell
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
'DC01','FileServer','FIN-PC','IT-PC' | %{ sq $_ 1 Image $ps 500 } | ?{ $_.CommandLine -match 'EncodedCommand' } |
  select Computer,UtcTime,User,@{n='Decoded';e={[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($_.CommandLine -split ' ')[-1]))}} |
  ?{ $_.Decoded -match 'localdisk' } | sort UtcTime | ft -auto
Get-Content "$A\FIN-PC\Users\Administrator\AppData\Local\Temp\localdisk.ps1"
```

<figure><img src="../img/zerologon/zl-12-localdisk-all-hosts.png" alt="Sysmon 4 máy: chạy localdisk.ps1"><figcaption>Sysmon của 4 máy: cùng một lệnh PowerShell mã hóa chạy dưới quyền SYSTEM từ 21:57:28 đến 21:59:32 UTC. Nội dung giải mã là .\localdisk.ps1.</figcaption></figure>

<figure><img src="../img/zerologon/zl-09-localdisk-script.png" alt="Nội dung localdisk.ps1"><figcaption>Nội dung localdisk.ps1 lấy từ thư mục Temp của Administrator trên FIN-PC. Script tạo C:\Data, liệt kê các thư mục con của một thư mục nguồn (đã làm mờ) và nén từng thư mục thành file zip bằng Compress-Archive.</figcaption></figure>

- **Nhận định:**
  - Script gom và nén dữ liệu vào một chỗ (giai đoạn Collection), thường là bước chuẩn bị trước khi đưa dữ liệu ra ngoài.
  - **Chưa đủ dữ liệu** để kết luận các file zip đã bị chuyển ra ngoài. Sysmon không ghi nhận kết nối mạng nào gắn với các file trong `C:\Data`.

## Dòng thời gian

- 02/01 11:11:37 UTC (18:11:37 UTC+7): `easygoing.exe` trên FIN-PC kết nối tới IP C2 qua TCP/80. Nguồn: Sysmon FIN-PC.
- 02/01 17:16:29 UTC (03/01 00:16:29 UTC+7): file `ChromeUpdate.ps1` được tạo trên FIN-PC. Nguồn: USN Journal FIN-PC.
- 02/01 19:50:32 UTC (03/01 02:50:32 UTC+7): PowerShell mã hóa recon Active Directory. Nguồn: Sysmon FIN-PC.
- 02/01 20:09:37 UTC (03:09:37 UTC+7): tải script qua `127.0.0.1:25816`, chạy `Invoke-ShareFinder`. Nguồn: Sysmon FIN-PC.
- 02/01 20:15:38 UTC (03:15:38 UTC+7): `ANONYMOUS LOGON` đặt lại mật khẩu `DC01$`. Nguồn: Security DC01.
- 02/01 20:22:26 đến 20:29:50 UTC (03:22 đến 03:29 UTC+7): `dlee` chạy lệnh qua WMI trên DC01, tắt Defender, bật RDP. Nguồn: Sysmon DC01.
- 02/01 20:44:53 UTC (03:44:53 UTC+7): `easygoing.exe` chạy bằng tài khoản `FIN-PC\Administrator`. Nguồn: Sysmon FIN-PC.
- 02/01 20:53:52 đến 21:13:06 UTC (03:53 đến 04:13 UTC+7): service tên ngẫu nhiên qua `ADMIN$` trên FIN-PC, IT-PC, FileServer, DC01. Nguồn: System log.
- 02/01 21:10:54 đến 21:12:44 UTC (04:10 đến 04:12 UTC+7): truy cập `lsass.exe` trên IT-PC, FileServer, FIN-PC. Nguồn: Sysmon.
- 02/01 21:12:44 UTC (04:12:44 UTC+7): leo quyền qua named pipe trên FIN-PC. Nguồn: Sysmon FIN-PC.
- 02/01 21:18:51 và 21:21:42 UTC (04:18 và 04:21 UTC+7): cài và đặt mật khẩu phần mềm điều khiển từ xa trên FileServer. Nguồn: System và Sysmon FileServer.
- 02/01 21:28:43 UTC (04:28:43 UTC+7): WMIC từ FIN-PC tới FileServer bằng `FileShareService`. Nguồn: Sysmon FIN-PC.
- 02/01 21:35:06 UTC (04:35:06 UTC+7): tạo scheduled task persistence trên FIN-PC. Nguồn: Sysmon FIN-PC.
- 02/01 21:57 đến 21:59 UTC (04:57 đến 04:59 UTC+7): chạy `localdisk.ps1` trên cả 4 máy. Nguồn: Sysmon, USN Journal.
