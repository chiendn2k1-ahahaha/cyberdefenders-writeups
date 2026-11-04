title: Yellow RAT
summary: Từ một hash mẫu, dùng VirusTotal và trang threat của Red Canary để gọi tên cụm mối đe dọa, lấy metadata của file và máy chủ C2.

# Yellow RAT

- **Lab:** [Yellow RAT](https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/) trên CyberDefenders. Nhóm Threat Intel, độ khó Easy, đã retired.
- **Dữ liệu:** file `hash.txt` chứa SHA-256 `30E527E4...0D071C85`. Bối cảnh: máy trạm của công ty GlobalTech Industries có lưu lượng ra ngoài đáng ngờ và truy vấn tìm kiếm của người dùng bị chuyển hướng.
- **Công cụ:** VirusTotal (tab Detection, Details, Behavior) và trang threat trong Threat Detection Report của Red Canary.
- **Quy ước:**
  - Ảnh là ảnh chụp trang VirusTotal và Red Canary, chụp ngày 04/11/2026. Giờ trên VirusTotal là UTC.
  - <span class="red">Khung đỏ</span> đánh dấu chỗ cần chú ý. Vùng làm mờ là đáp án (tên cụm, tên file, thời điểm, tên miền C2).

## Tóm tắt kết quả

- Hash ứng với một DLL .NET (Win32 DLL, Mono/.Net assembly, 68,00 KB). VirusTotal ghi nhận 55/71 engine phát hiện, family labels `msil`, `fful`, `polazert`.
- Red Canary theo dõi hoạt động này dưới một tên cụm riêng. Đây là cụm dùng search engine poisoning (đẩy trang độc lên kết quả tìm kiếm) để dụ người dùng cài một RAT .NET có chức năng đánh cắp thông tin. Các nhà nghiên cứu khác gọi cụm này bằng 3 tên khác.
- Tên file gốc của mẫu có dạng GUID (chuỗi định danh 32 ký tự hex) với đuôi `.dll`.
- Trong sandbox, chuỗi URL HTTPS của một tên miền xuất hiện trong bộ nhớ của mẫu. Đây là máy chủ C2.

## Bước 1: nhận diện họ mã độc

- **Mục tiêu:** biết mẫu thuộc họ nào trước khi tìm báo cáo.
- **Cách làm:** tra hash trên VirusTotal, xem tab Detection: Popular threat label, Family labels và nhãn của từng hãng.

<figure><img src="../img/yellow-rat/yr-02-vt-labels.png" alt="VirusTotal Detection: nhãn của các hãng"><figcaption>Tab Detection: 55/71 engine phát hiện. Popular threat label trojan.msil/fful, Family labels msil, fful, polazert. Alibaba ghi Trojan:MSIL/Polazert, ALYac ghi Trojan.MSIL.Polazer, ClamAV ghi Win.Trojan.Jupiter. Tên file của mẫu ở phần đầu trang đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Các nhãn `Polazert` và `Jupiter` là tên của cùng một họ RAT .NET.
  - Tag `assembly` và `pedll` cho biết đây là DLL viết bằng .NET.

## Bước 2: gọi tên cụm mối đe dọa theo Red Canary

- **Mục tiêu:** biết Red Canary gọi cụm hoạt động này là gì.
- **Cách làm:** tìm tên họ mã độc ở Bước 1 trong Threat Detection Report của Red Canary, mở trang của cụm tương ứng, đọc mục Analysis.

<figure><img src="../img/yellow-rat/yr-04-redcanary.png" alt="Red Canary: mục Analysis của trang threat"><figcaption>Mục Analysis trên trang threat của Red Canary. Đoạn mở đầu mô tả một activity cluster dùng search engine poisoning để lừa người dùng cài một .NET RAT có khả năng đánh cắp thông tin, được Red Canary báo cáo lần đầu năm 2020. Tên cụm và 3 tên mà nhà nghiên cứu khác dùng đã làm mờ.</figcaption></figure>

- **Nhận định:**
  - Một trong 3 tên khác trùng với nhãn Family labels trên VirusTotal ở Bước 1. Đây là cách nối mẫu với báo cáo của Red Canary.
  - Hướng giải: tên cụm là tiêu đề trang và từ đầu tiên của đoạn Analysis.

## Bước 3: tên file và các mốc thời gian

- **Mục tiêu:** lấy tên file gốc, thời điểm biên dịch và lần gửi đầu tiên.
- **Cách làm:** mở tab Details, xem mục History, Names và File Version Information.

<figure><img src="../img/yellow-rat/yr-01-vt-history-names.png" alt="VirusTotal Details: History, Names, File Version Information"><figcaption>Tab Details. History: Creation Time và First Submission đã làm mờ, First Seen In The Wild 2021-01-12 20:48:12 UTC. Names: dòng đầu là tên dạng GUID với đuôi .dll (đã làm mờ). File Version Information: Original Name và Internal Name là cùng tên GUID đó.</figcaption></figure>

- **Nhận định:**
  - Original Name trong thông tin phiên bản (File Version Information) trùng với tên đầu tiên trong mục Names. Đây là tên do người viết mã độc đặt lúc biên dịch.
  - Thời điểm biên dịch sớm hơn lần gửi đầu khoảng 3 tuần. First Seen In The Wild còn muộn hơn cả First Submission.
  - Hướng giải: Creation Time và First Submission đọc trực tiếp trong mục History, theo giờ UTC.

## Bước 4: máy chủ C2 và file trên đĩa

- **Mục tiêu:** xác định nơi mẫu kết nối tới và các file nó dùng.
- **Cách làm:** mở tab Behavior, xem mục Memory Pattern Domains, Memory Pattern Urls và Files Opened.

<figure><img src="../img/yellow-rat/yr-03-vt-memory-c2.png" alt="VirusTotal Behavior: Memory Pattern và Files Opened"><figcaption>Tab Behavior. Memory Pattern Domains và Memory Pattern Urls có một tên miền và một URL https:// (đã làm mờ). Files Opened: mẫu chạy từ C:\Users\&lt;USER&gt;\Desktop\attachment.dll và mở file C:\Users\user\AppData\Local\Temp\6e6d5103f997d6a7894290594b484f7a.exe.dll.</figcaption></figure>

- **Nhận định:**
  - Tên miền và URL HTTPS nằm sẵn trong bộ nhớ của mẫu khi chạy. Đây là địa chỉ C2 mà RAT dùng để nhận lệnh.
  - Mẫu ghi và mở file trong thư mục `%TEMP%` của người dùng, đúng hành vi đã được mô tả cho họ mã độc này.
  - VirusTotal không hiện file `.dat` mà lab hỏi. Tên file `.dat` cần lấy từ báo cáo sandbox khác hoặc từ bài phân tích của Red Canary về cách mẫu lưu module đã mã hóa.
  - Hướng giải: địa chỉ C2 là URL trong Memory Pattern Urls.
