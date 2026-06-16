#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[64];

    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);

    // Vấn đề Coverage Wall: Phải đoán đúng chuỗi BUG! và ADMIN
    if (strncmp(buffer, "BUG!", 4) == 0) {
        
        // Cần thêm ADMIN để đi sâu hơn
        if (strncmp(buffer + 4, "ADMIN", 5) == 0) {
            
            // Mô phỏng logic phân tích cú pháp phức tạp sinh ra nhiều path
            int i = 9;
            int authenticated = 0;
            while (i < 54) {
                if (strncmp(buffer + i, "USER", 4) == 0) {
                    i += 4;
                } else if (strncmp(buffer + i, "PASS", 4) == 0) {
                    i += 4;
                } else if (strncmp(buffer + i, "ROOT", 4) == 0) {
                    i += 4;
                } else if (strncmp(buffer + i, "CONF", 4) == 0) {
                    i += 4;
                } else if (strncmp(buffer + i, "SECRET_KEY", 10) == 0) {
                    authenticated = 1;
                    i += 10;
                } else {
                    i++;
                }
            }

            if (authenticated) {
                printf("Magic bytes BUG!ADMIN and SECRET_KEY found! Triggering crash...\n");
                abort(); 
            }
        }
    }

    printf("Normal execution completed.\n");
    return 0;
}
