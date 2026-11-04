title: Babble Loader
summary: Lần theo một loader x64 nhiều tầng bằng x64dbg: giải chuỗi XOR, API hashing và syscall trực tiếp, kiểm tra GPU chống sandbox, shellcode đếm tiến trình, rồi một bộ nạp .NET mã nguồn mở chạy payload sau khi vô hiệu AMSI.

# Babble Loader

- **Lab:** [Babble Loader](https://cyberdefenders.org/blueteam-ctf-challenges/babble-loader/) trên CyberDefenders. Nhóm Malware Analysis, độ khó Insane, 19 câu hỏi, đã retired.
- **Dữ liệu:** một file `invoices.exe` (PE64, 1.694.720 byte) trên máy ảo Windows Server 2016 của lab. Máy ảo không có internet.
- **Công cụ:**
  - x64dbg (breakpoint, lệnh `TraceIntoConditional` / `TraceOverConditional` ghi log từng lệnh ra file).
  - PowerShell để đọc header PE và lọc file trace.
- **Quy ước:**
  - Mẫu chỉ chạy bên trong x64dbg trên máy ảo của lab. Mọi patch đều ghi vào bộ nhớ tiến trình, không ghi ra file.
  - Ảnh là ảnh chụp màn hình máy lab. <span class="red">Khung đỏ</span> đánh dấu chỗ cần chú ý. Vùng làm mờ là đáp án.

## Tóm tắt kết quả

- `invoices.exe` là loader nhiều tầng, viết để làm khó cả phân tích tĩnh lẫn sandbox:
  - Chuỗi quan trọng (như `ntdll.dll`) được dựng trên stack rồi giải XOR khi chạy.
  - Hàm API được tìm theo giá trị hash. Nhiều hàm Nt* được gọi bằng lệnh `syscall` trực tiếp, bỏ qua hook của EDR (phần mềm giám sát endpoint) trong `ntdll.dll`.
  - Mẫu tạo đối tượng DXGI, đọc vendor ID của card màn hình và chỉ chạy tiếp nếu khớp một trong 3 giá trị cố định. Máy lab không khớp, nên mẫu tự gây lỗi truy cập bộ nhớ và dừng.
- Sau khi vượt kiểm tra GPU, mẫu giải mã shellcode tầng 1 vào vùng nhớ `0x190000`. Shellcode này gọi một hàm Nt* qua syscall để lấy danh sách tiến trình, đếm số tiến trình và dừng nếu số tiến trình không vượt ngưỡng.
- Tầng 2 là shellcode của một công cụ mã nguồn mở chuyên nạp .NET trong bộ nhớ. Nó nạp CLR, vá `AmsiScanBuffer` trong `amsi.dll`, rồi chạy một assembly .NET dài 0x1EC00 byte ngay trong tiến trình.

## Bước 1: header PE

- **Mục tiêu:** đọc subsystem và RVA của entry point.
- **Cách làm:** đọc trực tiếp các trường trong NT header bằng PowerShell. Offset tính từ `e_lfanew` (giá trị tại 0x3C): `+4` là Machine, `+24` là Magic của Optional Header, `+40` là AddressOfEntryPoint, `+48` là ImageBase (PE32+), `+92` là Subsystem.

<figure><img src="../img/babble-loader/bl-00-pe-header.png" alt="Đọc NT header bằng PowerShell"><figcaption>Machine 0x8664 (x64), Magic 0x020B (PE32+), ImageBase 0x140000000. Giá trị EntryPoint và Subsystem đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Subsystem là một số. Đáp án là tên hằng số tương ứng trong tài liệu PE format của Microsoft (dạng `IMAGE_SUBSYSTEM_...`).
  - AddressOfEntryPoint là RVA (địa chỉ tương đối so với ImageBase). Khi x64dbg dừng ở entry breakpoint, địa chỉ tuyệt đối bằng ImageBase cộng RVA này.

<figure><img src="../img/babble-loader/bl-01-entry.png" alt="x64dbg dừng ở entry point"><figcaption>x64dbg dừng ở "entry breakpoint", dòng .text cho biết đây là &lt;OptionalHeader.AddressOfEntryPoint&gt; (địa chỉ đã làm mờ). Code ở đây là stub CRT bình thường của MSVC.</figcaption></figure>

## Bước 2: chuỗi mã hóa XOR

- **Mục tiêu:** tìm key XOR ban đầu dùng để giải chuỗi `ntdll.dll`.
- **Cách làm:**
  - Đặt breakpoint ở `GetModuleHandleA` (hàm có trong bảng import). Khi dừng, RCX trỏ tới chuỗi `ntdll.dll` đã được giải mã.
  - Lệnh `rtr` (chạy tới lệnh return) đưa về hàm gọi ở `0x1400017B0`.

<figure><img src="../img/babble-loader/bl-02-xor-string.png" alt="Hàm giải chuỗi ntdll.dll"><figcaption>Hàm ở 0x1400017B0 ghi 10 byte mã hóa (E6 0C EC 14 E4 56 EC 14 E4 78) lên stack, rồi ghi một hằng 4 byte vào [rsp+24]. Hằng này là key ban đầu (đã làm mờ). Dump bên dưới cho thấy kết quả "ntdll.dll" sau vòng lặp giải mã.</figcaption></figure>

- **Nhận định:**
  - Key là một DWORD và được biến đổi sau mỗi vòng, nên câu hỏi hỏi "giá trị ban đầu".
  - Hướng giải: hằng số trong lệnh `mov dword ptr ss:[rsp+24], ...` ngay sau 10 lệnh `mov byte ptr`.

## Bước 3: API hashing và syscall trực tiếp

- **Mục tiêu:** hiểu cách mẫu tìm hàm Nt* và gọi syscall.
- **Cách làm:**
  - Các hàm resolver nhận một giá trị hash 4 byte, duyệt bảng export của `ntdll.dll`, băm từng tên hàm và so với giá trị đó.
  - Khi tìm thấy, resolver trả về số syscall (số hiệu dịch vụ của kernel) và một địa chỉ lệnh `syscall` bên trong `ntdll.dll`. Mẫu tự đặt số syscall vào EAX rồi nhảy tới địa chỉ này.
  - Ảnh trace ở Bước 6 cho thấy cơ chế đó: `mov eax, dword ptr ds:[r11]` lấy số syscall, `jmp qword ptr ds:[r11+0x10]` nhảy tới lệnh `syscall` ở `0x7FFC90E76862`.
- **Nhận định:**
  - Gọi syscall theo cách này bỏ qua các hook mà EDR đặt ở đầu hàm trong `ntdll.dll`. Breakpoint đặt ở tên hàm Nt* cũng không bao giờ dừng.
  - Hướng giải cho các câu về hash của `RtlAllocateHeap`, hash 0x45E1B380 và 0x89DD5E00: đặt breakpoint ở hàm resolver, xem hash nào cho ra hàm nào. Sau đó đặt breakpoint ở lệnh `syscall` để đọc EAX (số syscall) và RDX (tham số thứ hai).

## Bước 4: kiểm tra GPU bằng DXGI

- **Mục tiêu:** tìm GUID của IDXGIFactory, method đầu tiên được gọi và 3 vendor ID mà mẫu chấp nhận.
- **Cách làm:**
  - Đặt breakpoint ở `CreateDXGIFactory`. Tham số đầu (RCX) trỏ tới GUID của interface cần tạo.
  - Sau đó trace lệnh từ `CreateDXGIFactory` cho tới khi mẫu tự gây lỗi, ghi mọi lệnh ra `trace.txt` (1.340 dòng), rồi lọc các lệnh `cmp` có hằng số.

<figure><img src="../img/babble-loader/bl-03-guid.png" alt="GUID truyền vào CreateDXGIFactory"><figcaption>Dừng ở dxgi!CreateDXGIFactory, dump tại địa chỉ trong RCX. 16 byte đầu là GUID theo thứ tự little-endian. 6 byte cuối đã làm mờ.</figcaption></figure>

<figure><img src="../img/babble-loader/bl-04-vendor-trace.png" alt="Lọc trace tìm lệnh so sánh vendor ID"><figcaption>3 lệnh cmp ở 0x140171A24, 0x140171A34, 0x140171A44 so vendor ID (lưu ở [rsp+0x1FB00]) với 3 giá trị nạp vào EAX (đã làm mờ). Mỗi lệnh cmp đi kèm một lệnh jz/jnz. Khi không khớp giá trị nào, mẫu nhảy tới 0x140171D4D và sau đó tự đọc địa chỉ không hợp lệ.</figcaption></figure>

- **Nhận định:**
  - Kiểm tra lặp 2 lần vì mẫu duyệt qua từng adapter (gọi method lấy adapter với chỉ số 0, 1). Máy lab không có adapter nào khớp.
  - Trên máy lab, lỗi xuất hiện ở `0x1401767BD` (`EXCEPTION_ACCESS_VIOLATION`). Đây là cách mẫu "chết" có chủ đích để tránh sandbox.
  - Hướng giải:
    - GUID: 6 byte cuối trong dump ở trên.
    - Method đầu tiên: method mà mẫu gọi qua vtable ngay sau `CreateDXGIFactory`, dùng để lấy adapter theo chỉ số. Tên có dạng `IDXGIFactory::...`.
    - 3 vendor ID: giá trị EAX ở 3 dòng cmp, theo đúng thứ tự địa chỉ.

## Bước 5: vượt kiểm tra GPU

- **Mục tiêu:** cho mẫu chạy tiếp để quan sát tầng shellcode.
- **Cách làm:**
  - Đoạn code này tự giải mã khi chạy. Patch đặt sớm ở entry point bị ghi đè, mẫu vẫn chết.
  - Cách làm được: dừng ở `CreateDXGIFactory` (lúc code đã giải xong), rồi đổi `jz` ở `0x140171A2B` thành `jmp 0x140171A51` bằng lệnh `asm`.

<figure><img src="../img/babble-loader/bl-05-patch.png" alt="Patch jz thành jmp"><figcaption>Sau patch, lệnh ở 0x140171A2B thành "jmp invoices.140171A51", đi thẳng vào nhánh của máy thật. Patch chỉ nằm trong bộ nhớ.</figcaption></figure>

## Bước 6: shellcode tầng 1

- **Mục tiêu:** tìm API dùng để thu thập thông tin hệ thống, tham số đầu của nó và ngưỡng số tiến trình.
- **Cách làm:**
  - Đặt hardware breakpoint thực thi ở `0x190000`. Sau patch, mẫu dừng ở đây sau 6.410 lệnh kể từ chỗ so sánh vendor ID.
  - Trace vào trong shellcode cho tới khi quay về module chính: 73.754 dòng log, trong đó 10.381 dòng thuộc vùng shellcode.

<figure><img src="../img/babble-loader/bl-06-stage1-trace.png" alt="Trace shellcode tầng 1"><figcaption>Đầu shellcode: lea ecx,[rbx+...] đặt tham số đầu, call 0x190197 chuyển vào stub syscall: mov r10,rcx; mov eax,[r11] (số syscall); jmp [r11+0x10] tới lệnh syscall trong ntdll. Lần gọi đầu trả về 0xC0000004 (buffer quá nhỏ), mẫu cấp phát lại và gọi lần hai. Cuối cùng là lệnh cmp ebp,&lt;ngưỡng&gt; ở 0x190127 (các giá trị đã làm mờ).</figcaption></figure>

- **Nhận định:**
  - Mẫu gọi cùng một syscall 2 lần. Lần đầu nhận mã 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH), dùng kích thước trả về để cấp phát buffer bằng `RtlAllocateHeap` (lệnh `call rdi`), rồi gọi lại. Đây là mẫu gọi điển hình của các hàm truy vấn thông tin hệ thống.
  - Kết quả là danh sách tiến trình. Mẫu đếm số tên tiến trình khác nhau vào EBP.
  - Hướng giải:
    - API: hàm Nt* có số syscall nằm trong EAX lúc gọi `syscall`, trên Windows Server 2016 bản 14393.
    - Tham số đầu: giá trị ECX, tra trong enum `SYSTEM_INFORMATION_CLASS` của MSDN để ra tên lớp thông tin.
    - Ngưỡng: hằng trong lệnh `cmp ebp, ...` ở 0x190127.

<figure><img src="../img/babble-loader/bl-07-proc-threshold.png" alt="So sánh số tiến trình"><figcaption>Dừng ở 0x190127. Máy lab có EBP = 0x2A (42 tiến trình khác nhau), không vượt ngưỡng (đã làm mờ), nên jle 190131 nhảy sang nhánh thoát. Đoạn dưới (từ 0x190137) là vòng lặp giải mã tầng 2: cộng, xoay bit rồi ghi lại từng byte, chạy tới khi rbx = 0x12185.</figcaption></figure>

- **Nhận định:**
  - Để chạy tiếp, tôi đổi EBP thành 0x100 (lệnh `ebp=0x100`). Thay đổi này chỉ có tác dụng trong lần chạy đó.
  - Vòng lặp giải mã đọc dữ liệu tại `[rsi+8]` cộng offset, nằm ngay sau phần code của shellcode tầng 1. Hướng giải cho câu về offset tầng 2: xem shellcode trỏ R9/RSI tới đâu trước vòng lặp này, tính so với đầu vùng `0x190000`.

## Bước 7: bộ nạp .NET và vô hiệu AMSI

- **Mục tiêu:** xác định công cụ nạp .NET, lệnh vá AMSI và phiên bản CLR.
- **Cách làm:**
  - Đặt breakpoint ở `AmsiScanBuffer` và `LoadLibraryA`, cho chạy tiếp.
  - Tìm trong bộ nhớ chuỗi `ole32;oleaut32` (lệnh `findallmem`).

<figure><img src="../img/babble-loader/bl-08-loader-dlls.png" alt="Chuỗi DLL của bộ nạp"><figcaption>Vùng nhớ 0x1B01F0 chứa chuỗi "ole32;oleaut32;shell32;mscoree;kernel32", danh sách DLL ngăn cách bằng dấu chấm phẩy. Đây là định dạng cấu hình đặc trưng của một bộ nạp .NET mã nguồn mở.</figcaption></figure>

<figure><img src="../img/babble-loader/bl-09-clr-amsi-log.png" alt="Log x64dbg: amsi.dll và CLR"><figcaption>Log x64dbg: tiến trình nạp amsi.dll, rồi mscoreei.dll và clr.dll trong Microsoft.NET\Framework64\&lt;phiên bản&gt;\ (đã làm mờ), sau đó phát sinh exception CLRDBG_NOTIFICATION của CLR.</figcaption></figure>

<figure><img src="../img/babble-loader/bl-10-amsi-patch.png" alt="AmsiScanBuffer sau khi bị vá"><figcaption>Disassembly của amsi!AmsiScanBuffer tại 0x7FFC6BC72430: 2 lệnh đầu đã bị ghi đè (byte và lệnh đã làm mờ). Phần thân gốc của hàm vẫn còn bên dưới nhưng không bao giờ chạy tới.</figcaption></figure>

- **Nhận định:**
  - Chuỗi DLL ngăn bằng dấu chấm phẩy, cách nạp CLR rồi vá AMSI khớp với mã nguồn công khai của một shellcode generator nổi tiếng dùng để chạy .NET, PE và script trong bộ nhớ. Hướng giải: tìm chuỗi DLL này trên GitHub để ra tên công cụ.
  - Lệnh vá đặt mã lỗi vào RAX rồi trả về ngay. Hàm gọi nhận mã lỗi đó và bỏ qua việc quét.
  - Hướng giải: lệnh vá là 2 lệnh đầu của `AmsiScanBuffer` trong ảnh. Phiên bản CLR là tên thư mục chứa `clr.dll`.

## Bước 8: payload .NET cuối cùng

- **Mục tiêu:** trích payload .NET, tính SHA-256 và xác định họ mã độc.
- **Cách làm:**
  - Tìm header `MZ` trong vùng nhớ của bộ nạp: có ở `0x1C0528`.
  - Lưu 0x80000 byte từ đó ra file bằng `savedata`, đọc section table để biết kích thước thật: `.text`, `.rsrc`, `.reloc`, kết thúc ở 0x1EC00 (125.952 byte).
  - Kiểm tra lại bằng trường độ dài mà bộ nạp ghi ngay trước header MZ: cũng là 0x1EC00.

<figure><img src="../img/babble-loader/bl-11-payload.png" alt="Payload .NET đã trích"><figcaption>Độ dài bộ nạp ghi trước MZ là 0x1EC00, khớp section table. Metadata .NET (chữ ký BSJB) ở offset 0xBC2C, chuỗi phiên bản ngay sau đó (đã làm mờ). SHA-256 của file đã trích cũng đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Tôi trích payload 2 cách (theo độ dài bộ nạp ghi và theo section table) và cả 2 cho cùng kích thước. Tuy vậy, SHA-256 tôi tính được không khớp với mẫu đáp án mà đề bài gợi ý (6 byte đầu). Vì vậy giá trị hash phụ thuộc vào đúng vùng nhớ bạn dump. Walkthrough chính thức dump buffer mà bộ nạp đưa cho CLR bằng lệnh `savedata`.
  - Hash tôi tính chưa có trên VirusTotal, và chuỗi trong assembly đã bị làm rối. Vì vậy tôi chưa tự xác nhận được họ mã độc trên máy lab. Hướng giải: tra hash đúng trên VirusTotal, xem nhãn của các engine (dạng `MSIL/...`) để ra tên infostealer.
  - Kích thước shellcode giải mã (câu về payload nhúng): cộng kích thước các đoạn mà lệnh `rep movsb` chép vào vùng nhớ do `NtMapViewOfSection` tạo ra. Đặt hardware breakpoint ghi lên vùng nhớ đó để bắt từng lần chép.

## Dòng thời gian thực thi

| Thứ tự | Vị trí | Sự kiện | Bằng chứng |
|---|---|---|---|
| 1 | Entry point (stub CRT) | Bắt đầu chạy | x64dbg entry breakpoint |
| 2 | 0x1400017B0 | Giải chuỗi `ntdll.dll` bằng XOR, gọi `GetModuleHandleA` | Disassembly, dump RCX |
| 3 | Hàm resolver | Tìm hàm Nt* theo hash, lấy số syscall | Trace, lệnh `mov eax,[r11]` |
| 4 | `CreateDXGIFactory` | Tạo DXGI factory, liệt kê adapter | Breakpoint, GUID trong RCX |
| 5 | 0x140171A24–0x140171A44 | So vendor ID với 3 giá trị, sai thì tự gây lỗi | `trace.txt`, 1.340 dòng |
| 6 | 0x190000 | Shellcode tầng 1 chạy, gọi syscall lấy danh sách tiến trình | `trace3.txt`, 73.754 dòng |
| 7 | 0x190127 | So số tiến trình với ngưỡng, giải mã tầng 2 | Breakpoint phần cứng |
| 8 | Tầng 2 (bộ nạp .NET) | Nạp `amsi.dll`, CLR, vá `AmsiScanBuffer` | Log x64dbg, disassembly |
| 9 | 0x1C0528 | Payload .NET 0x1EC00 byte được nạp trong bộ nhớ | `savedata`, section table |
