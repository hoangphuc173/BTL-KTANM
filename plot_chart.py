import matplotlib.pyplot as plt
import os

def parse_plot_data(file_path):
    times = []
    paths = []
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return times, paths
        
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 4:
                try:
                    rel_time = int(parts[0])
                    corpus_count = int(parts[3])
                    
                    # Convert time to minutes
                    times.append(rel_time / 60.0)
                    paths.append(corpus_count)
                except ValueError:
                    continue
    return times, paths

# Đọc dữ liệu thật từ thư mục output
times_no_dict, paths_no_dict = parse_plot_data('output_no_dict/default/plot_data')
times_with_dict, paths_with_dict = parse_plot_data('output_with_dict/default/plot_data')

plt.figure(figsize=(10, 6))

if times_no_dict and paths_no_dict:
    plt.plot(times_no_dict, paths_no_dict, label="Không có từ điển (AFL++ Mặc định)", color='red', linestyle='dashed', linewidth=2)

if times_with_dict and paths_with_dict:
    plt.plot(times_with_dict, paths_with_dict, label="Có từ điển (AFL++ + Angr Dict)", color='green', linewidth=2)

plt.title('So sánh hiệu năng Fuzzing (Paths Found / Time)', fontsize=14, fontweight='bold')
plt.xlabel('Thời gian Fuzzing (Phút)', fontsize=12)
plt.ylabel('Số lượng Code Paths tìm thấy', fontsize=12)

max_path = 0
if paths_no_dict: max_path = max(max_path, max(paths_no_dict))
if paths_with_dict: max_path = max(max_path, max(paths_with_dict))
plt.yticks(range(0, int(max_path) + 2))

plt.legend(fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()

plt.savefig('fuzzing_comparison_chart.png', dpi=300)
print("[+] Đã xuất biểu đồ ra file fuzzing_comparison_chart.png")
