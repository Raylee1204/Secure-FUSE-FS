/**
* Less Simple, Yet Stupid Filesystem with AES-256 Encryption.
* Modified to include AES encryption and detailed logs.
*/

#define FUSE_USE_VERSION 30
#define MAX_FILES 256
#define MAX_CONTENT_SIZE 1024
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

char dir_list[256][256];
int curr_dir_idx = -1;

char files_list[MAX_FILES][256];
unsigned char files_content[MAX_FILES][MAX_CONTENT_SIZE];
int files_size[MAX_FILES];
unsigned char file_keys[MAX_FILES][AES_KEY_SIZE];
unsigned char file_ivs[MAX_FILES][AES_IV_SIZE];
int curr_file_idx = -1;

// Function prototypes
void aes_encrypt(int file_idx, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);
void aes_decrypt(int file_idx, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);

void add_dir(const char *dir_name) {
    curr_dir_idx++;
    if (curr_dir_idx < 256) {
        strcpy(dir_list[curr_dir_idx], dir_name);
        printf("[MKDIR] Added directory: %s\n", dir_name);
    } else {
        printf("[MKDIR] Error: Maximum directory limit reached.\n");
    }
}

// Add a new file and generate unique key/IV
void add_file(const char *filename, const char *content) {
    curr_file_idx++;
    if (curr_file_idx < MAX_FILES) {
        strcpy(files_list[curr_file_idx], filename);
	strcpy(files_list[curr_file_idx], filename);
        RAND_bytes(file_keys[curr_file_idx], AES_KEY_SIZE);
        RAND_bytes(file_ivs[curr_file_idx], AES_IV_SIZE);
        printf("[CREATE] Generated key and IV for file: %s\n", filename);
    } else {
        printf("[CREATE] Maximum file limit reached!\n");
    }
}

// AES encryption function
void aes_encrypt(int file_idx, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!ctx) {
        perror("[AES] Failed to create encryption context");
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_keys[file_idx], file_ivs[file_idx]) != 1) {
        perror("[AES] Encryption initialization failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1) {
        perror("[AES] Encryption update failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len = len;

    if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) {
        perror("[AES] Encryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);
    printf("[AES] Data encrypted successfully.\n");
}

// AES decryption function
void aes_decrypt(int file_idx, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!ctx) {
        perror("[AES] Failed to create decryption context");
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_keys[file_idx], file_ivs[file_idx]) != 1) {
        perror("[AES] Decryption initialization failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptUpdate(ctx, output, &len, input, input_len) != 1) {
        perror("[AES] Decryption update failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len = len;

    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
        perror("[AES] Decryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);
    printf("[AES] Data decrypted successfully.\n");
}


static int do_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    memset(st, 0, sizeof(struct stat));

    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = time(NULL);
    st->st_mtime = time(NULL);

    printf("[GETATTR] Called for path: %s\n", path);

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }

    for (int i = 0; i <= curr_file_idx; i++) {
        if (strcmp(path + 1, files_list[i]) == 0) {
            st->st_mode = S_IFREG | 0644;
            st->st_nlink = 1;
            st->st_size = strlen(files_content[i]);
            printf("[GETATTR] File found: %s\n", files_list[i]);
            return 0;
        }
    }

    for (int i = 0; i <= curr_dir_idx; i++) {
        if (strcmp(path + 1, dir_list[i]) == 0) {
            st->st_mode = S_IFDIR | 0755;
            st->st_nlink = 2;
            printf("[GETATTR] Directory found: %s\n", dir_list[i]);
            return 0;
        }
    }

    return -ENOENT;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;

    if (strcmp(path, "/") != 0) {
        return -ENOENT;
    }

    filler(buffer, ".", NULL, 0, 0);
    filler(buffer, "..", NULL, 0, 0);
    for (int i = 0; i <= curr_file_idx; i++) {
        filler(buffer, files_list[i], NULL, 0, 0);
    }
    printf("[READDIR]Listing directories: \n");
    for (int i = 0; i <= curr_dir_idx; i++) {
    printf(" - %s\n", dir_list[i]);
    filler(buffer, dir_list[i], NULL, 0, 0);
    }

    return 0;
}

// Read operation
static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)fi;

    unsigned char decrypted[MAX_CONTENT_SIZE];
    size_t decrypted_len;

    for (int i = 0; i <= curr_file_idx; i++) {
        if (strcmp(path + 1, files_list[i]) == 0) {
            aes_decrypt(i, files_content[i] + offset, files_size[i] - offset, decrypted, &decrypted_len);

            if (offset >= decrypted_len) {
                return 0;
            }

            if (offset + size > decrypted_len) {
                size = decrypted_len - offset;
            }

            memcpy(buffer, decrypted + offset, size);
            printf("[READ] Decrypted data read from file: %s\n", files_list[i]);
            return size;
        }
    }

    return -ENOENT;
}

static int do_mkdir(const char *path, mode_t mode) {
    (void)mode; // 模擬模式參數
    printf("Creating directory : %s\n", path);

    if (strcmp(path, "/") == 0) {
    printf("Cannot create root directory\n");
        return -EEXIST; // 根目錄已存在
    }

    for (int i = 0; i <= curr_dir_idx; i++) {
        if (strcmp(path + 1, dir_list[i]) == 0) {
        printf("The File name EXIST");
            return -EEXIST; // 目錄已存在
        }
    }
    // 確保目錄名稱有效
    if (strlen(path + 1) > 0) {
        add_dir(path + 1); // 添加到目錄清單
    printf("Directory added successfully: %s\n", path + 1); // 確認目錄添加
        return 0;          // 成功
    }
    printf("Invalid directory name\n");

    return -ENOENT; // 錯誤，無效的目錄名稱
}

static int do_rmdir(const char *path) {
    for (int i = 0; i <= curr_dir_idx; i++) {
        if (strcmp(path + 1, dir_list[i]) == 0) {
            // 移除目錄
            for (int j = i; j < curr_dir_idx; j++) {
                strcpy(dir_list[j], dir_list[j + 1]);
            }
            curr_dir_idx--;
            return 0;
        }
    }
    return -ENOENT;
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev) {
    (void)mode;
    (void)rdev;

    for (int i = 0; i <= curr_file_idx; i++) {
        if (strcmp(path + 1, files_list[i]) == 0) {
            return -EEXIST; // 檔案已存在
        }
    }

    add_file(path + 1,"");
    return 0;
}

// Write operation
static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info) {
    (void)info;

    unsigned char encrypted[MAX_CONTENT_SIZE];
    size_t encrypted_len;

    for (int i = 0; i <= curr_file_idx; i++) {
        if (strcmp(path + 1, files_list[i]) == 0) {
            aes_encrypt(i, (const unsigned char *)buffer, size, encrypted, &encrypted_len);
            memcpy(files_content[i] + offset, encrypted, encrypted_len);
            files_size[i] = offset + encrypted_len;

            // Write encrypted content to external file
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "/usr/src/test_tmp/%s", path + 1);
            FILE *fp = fopen(filepath, "wb");
            if (fp) {
                fwrite(encrypted, 1, encrypted_len, fp);
                fclose(fp);
                printf("[WRITE] Encrypted data written to: %s\n", filepath);
            } else {
                perror("[WRITE] Failed to write encrypted data to external file");
            }

            return size;
        }
    }

    return -ENOENT;
}

static int do_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
    (void)path;
    (void)ts;
    (void)fi;

    // 模擬成功
    return 0;
}

static int do_open(const char *path, struct fuse_file_info *fi) {
    for (int i = 0; i <= curr_file_idx; i++) {
        if (strcmp(path + 1, files_list[i]) == 0) return 0;
    }
    return -ENOENT;
}

static struct fuse_operations operations = {
    .getattr = do_getattr,
    .readdir = do_readdir,
    .read = do_read,
    .mkdir = do_mkdir,
    .mknod = do_mknod,
    .rmdir = do_rmdir,
    .write = do_write,
    .utimens = do_utimens,
    .open = do_open,
};

int main(int argc, char *argv[]) {
    // 檢查並建立指定路徑（用於儲存加密後的檔案）
    struct stat st = {0};
    if (stat("/usr/src/test_tmp", &st) == -1) {
        mkdir("/usr/src/test_tmp", 0755);
        printf("[INIT] Directory /usr/src/test_tmp created.\n");
    }

    // 添加檔案，生成密鑰和 IV
    add_file("example.txt", "");

    // 模擬寫入操作，調用 do_write
    const char *initial_content = "This is an example file. \n";
    size_t content_size = strlen(initial_content);

    struct fuse_file_info fi;
    do_write("/example.txt", initial_content, content_size, 0, &fi);

    printf("[INIT] Filesystem initialized with AES-256 encryption.\n");
    return fuse_main(argc, argv, &operations, NULL);
                                      
}

    
