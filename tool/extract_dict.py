import angr
import sys
import struct
import string

def extract_dictionary(binary_path, output_dict_path):
    print(f"[*] Loading binary: {binary_path}")
    # Load the binary
    p = angr.Project(binary_path, auto_load_libs=False)
    
    print("[*] Generating Control Flow Graph (CFG)...")
    # Generate CFG to analyze blocks
    cfg = p.analyses.CFGFast(normalize=True)
    
    print("[*] Extracting constants and magic bytes from basic blocks...")
    constants = set()
    
    for node in list(cfg.graph.nodes()):
        if not node.block:
            continue
            
        # Parse the VEX IR for this block
        try:
            vex_block = node.block.vex
            # Iterate through all statements in the VEX IR block
            for stmt in vex_block.statements:
                # We can look at all expressions in the statement
                for expr in stmt.expressions:
                    if expr.tag == 'Iex_Const':
                        val = expr.con.value
                        size = expr.con.size
                        
                        # Only care about constants that are 1 byte to 8 bytes (typical for magic bytes/integers)
                        if size in (8, 16, 32, 64):
                            try:
                                # Try to convert the value to bytes
                                num_bytes = size // 8
                                b = val.to_bytes(num_bytes, byteorder='little')
                                constants.add(b)
                                b_big = val.to_bytes(num_bytes, byteorder='big')
                                constants.add(b_big)
                            except Exception:
                                pass
        except Exception as e:
            pass

    # 2. Quét các phần bộ nhớ/tệp nhị phân tìm Strings (Kèm tính năng Dictionary Pruning)
    print("[*] Extracting readable strings from binary...")
    with open(binary_path, "rb") as f:
        data = f.read()
        current_string = bytearray()
        for byte in data:
            if 32 <= byte <= 126:
                current_string.append(byte)
            else:
                if 4 <= len(current_string) <= 16:
                    try:
                        text = current_string.decode('ascii')
                        # Kỹ thuật Pruning: Bỏ qua các chuỗi rác của file ELF (bắt đầu bằng dấu chấm) 
                        # và các hàm libc thông thường, ưu tiên chuỗi in hoa hoặc có ký tự đặc biệt
                        if not text.startswith('.') and not text.islower():
                            constants.add(bytes(current_string))
                    except:
                        pass
                current_string = bytearray()
        if 4 <= len(current_string) <= 16:
            constants.add(bytes(current_string))

    # 3. Ghi vào file từ điển định dạng AFL++ (Áp dụng Dictionary Pruning)
    print(f"[*] Writing dictionary to {output_dict_path}...")
    with open(output_dict_path, 'w') as f:
        idx = 0
        for c in constants:
            if not c or set(c) == {0}: continue
            
            # Chỉ giữ lại các chuỗi có chứa từ 3 ký tự in được trở lên (Khả năng cao là Magic Bytes)
            printable = sum(1 for b in c if 32 <= b <= 126)
            if printable >= 3 and len(c) <= 16:
                try:
                    text = c.decode('ascii')
                    if text.startswith('.') or "GLIBC" in text or "GCC" in text:
                        continue
                except:
                    pass
                hex_str = "".join([f"\\x{b:02x}" for b in c])
                f.write(f'dict_{idx}="{hex_str}"\n')
                idx += 1
                
            
    print(f"[+] Dictionary successfully extracted with {idx} entries!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <binary_file> <output_dict>")
        sys.exit(1)
        
    extract_dictionary(sys.argv[1], sys.argv[2])
