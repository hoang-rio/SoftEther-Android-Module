/**
 * FileIO stub for Android - Minimal implementation
 * This provides stub functions for file operations
 */

#include "stubs.h"
#include <Mayaqua/Mayaqua.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

// Hamcore stub functions
void InitHamcore()
{
}

void FreeHamcore()
{
}

void LoadHamcore(char *filename)
{
    (void)filename;
}

void LoadHamcoreWithConfigPath(char *config_path)
{
    (void)config_path;
}

void LoadHamcoreWithLang(char *filename, char *lang)
{
    (void)filename;
    (void)lang;
}

BUF *ReadHamcore(char *name)
{
    (void)name;
    return NULL;
}

BUF *ReadHamcoreW(wchar_t *name)
{
    (void)name;
    return NULL;
}

// Hamcore file builder
void HamcoreBuilder(char *dst, char *src)
{
    (void)dst;
    (void)src;
}

void HamcoreBuilderMain(char *dst, char *src)
{
    (void)dst;
    (void)src;
}

void HamcoreBuilderFileList(HC_LIST *list, char *dirname)
{
    (void)list;
    (void)dirname;
}

// Configuration directory
void SetConfigDir(char *name)
{
    (void)name;
}

void GetConfigDir(char *name, UINT size)
{
    if (name == NULL || size == 0) return;

    // Use Android app data directory
    char *home = getenv("HOME");
    if (home != NULL)
    {
        StrCpy(name, size, home);
    }
    else
    {
        StrCpy(name, size, "/data/data");
    }
}

void GetConfigDirW(wchar_t *name, UINT size)
{
    if (name == NULL || size == 0) return;

    char tmp[MAX_PATH];
    GetConfigDir(tmp, sizeof(tmp));
    StrToUni(name, size, tmp);
}

// DB directory
void GetDbDir(char *name, UINT size)
{
    GetConfigDir(name, size);
}

void GetDbDirW(wchar_t *name, UINT size)
{
    GetConfigDirW(name, size);
}

// Log directory
void GetLogDir(char *name, UINT size)
{
    if (name == NULL || size == 0) return;

    char config[MAX_PATH];
    GetConfigDir(config, sizeof(config));
    Format(name, size, "%s/logs", config);
}

void GetLogDirW(wchar_t *name, UINT size)
{
    if (name == NULL || size == 0) return;

    char tmp[MAX_PATH];
    GetLogDir(tmp, sizeof(tmp));
    StrToUni(name, size, tmp);
}

// Default build configuration file
void GetDefaultBuildConfigurationFile(char *name, UINT size)
{
    (void)name;
    (void)size;
}

// Current directory
void GetCurrentDir(char *name, UINT size)
{
    if (name == NULL || size == 0) return;

    if (getcwd(name, size) == NULL)
    {
        StrCpy(name, size, "/");
    }
}

void GetCurrentDirW(wchar_t *name, UINT size)
{
    if (name == NULL || size == 0) return;

    char tmp[MAX_PATH];
    GetCurrentDir(tmp, sizeof(tmp));
    StrToUni(name, size, tmp);
}

// File path helpers
void GetExeDir(char *name, UINT size)
{
    GetConfigDir(name, size);
}

void GetExeDirW(wchar_t *name, UINT size)
{
    GetConfigDirW(name, size);
}

void GetExeName(char *name, UINT size)
{
    if (name == NULL || size == 0) return;
    StrCpy(name, size, "softether");
}

void GetExeNameW(wchar_t *name, UINT size)
{
    if (name == NULL || size == 0) return;
    UniStrCpy(name, size, L"softether");
}

// Temp directory
void GetTempDir(char *name, UINT size)
{
    if (name == NULL || size == 0) return;
    StrCpy(name, size, "/tmp");
}

void GetTempDirW(wchar_t *name, UINT size)
{
    if (name == NULL || size == 0) return;
    UniStrCpy(name, size, L"/tmp");
}

// File operations
bool FileDelete(char *name)
{
    if (name == NULL) return false;
    return (unlink(name) == 0);
}

bool FileDeleteW(wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return FileDelete(tmp);
}

bool MakeDir(char *name)
{
    if (name == NULL) return false;
    return (mkdir(name, 0755) == 0 || errno == EEXIST);
}

bool MakeDirW(wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return MakeDir(tmp);
}

bool MakeDirEx(char *name)
{
    if (name == NULL) return false;

    char tmp[MAX_PATH];
    StrCpy(tmp, sizeof(tmp), name);

    // Create parent directories
    for (char *p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            MakeDir(tmp);
            *p = '/';
        }
    }
    return MakeDir(tmp);
}

bool MakeDirExW(wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return MakeDirEx(tmp);
}

void MakeDirFromFilePath(char *name)
{
    if (name == NULL) return;

    char dir[MAX_PATH];
    GetDirNameFromFilePath(dir, sizeof(dir), name);
    MakeDirEx(dir);
}

void MakeDirFromFilePathW(wchar_t *name)
{
    if (name == NULL) return;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    MakeDirFromFilePath(tmp);
}

// Directory operations
bool DeleteDir(char *name)
{
    if (name == NULL) return false;
    return (rmdir(name) == 0);
}

bool DeleteDirW(wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return DeleteDir(tmp);
}

// File existence
bool IsFileExists(char *name)
{
    if (name == NULL) return false;
    struct stat st;
    return (stat(name, &st) == 0 && S_ISREG(st.st_mode));
}

bool IsFileExistsW(wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return IsFileExists(tmp);
}

bool IsDirExists(char *name)
{
    if (name == NULL) return false;
    struct stat st;
    return (stat(name, &st) == 0 && S_ISDIR(st.st_mode));
}

bool IsDirExistsW(wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return IsDirExists(tmp);
}

// File size
UINT64 FileSize(char *name)
{
    if (name == NULL) return 0;
    struct stat st;
    if (stat(name, &st) != 0) return 0;
    return (UINT64)st.st_size;
}

UINT64 FileSizeW(wchar_t *name)
{
    if (name == NULL) return 0;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return FileSize(tmp);
}

// File time
UINT64 FileModifiedTime(char *name)
{
    if (name == NULL) return 0;
    struct stat st;
    if (stat(name, &st) != 0) return 0;
    return (UINT64)st.st_mtime * 1000ULL;
}

UINT64 FileModifiedTimeW(wchar_t *name)
{
    if (name == NULL) return 0;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return FileModifiedTime(tmp);
}

// Read dump
BUF *ReadDump(char *name)
{
    if (name == NULL) return NULL;

    IO *io = FileOpen(name, false);
    if (io == NULL) return NULL;

    UINT64 size = FileSize(name);
    if (size > MAX_SIZE)
    {
        FileClose(io, false);
        return NULL;
    }

    BUF *buf = NewBuf();
    void *tmp = Malloc((size_t)size);
    if (FileRead(io, tmp, (size_t)size) == (size_t)size)
    {
        WriteBuf(buf, tmp, (size_t)size);
        SeekBufToBegin(buf);
    }
    Free(tmp);
    FileClose(io, false);

    return buf;
}

BUF *ReadDumpW(wchar_t *name)
{
    if (name == NULL) return NULL;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return ReadDump(tmp);
}

// Write dump
bool DumpData(void *data, UINT size, char *name)
{
    if (data == NULL || name == NULL) return false;

    IO *io = FileCreate(name);
    if (io == NULL) return false;

    bool ret = (FileWrite(io, data, size) == size);
    FileClose(io, ret);
    return ret;
}

bool DumpDataW(void *data, UINT size, wchar_t *name)
{
    if (name == NULL) return false;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return DumpData(data, size, tmp);
}

// File open/create
IO *FileCreate(char *name)
{
    if (name == NULL) return NULL;

    MakeDirFromFilePath(name);

    int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return NULL;

    IO *io = Malloc(sizeof(IO));
    io->fd = fd;
    io->Name = CopyStr(name);
    io->WriteMode = true;
    io->HamMode = false;

    return io;
}

IO *FileCreateW(wchar_t *name)
{
    if (name == NULL) return NULL;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return FileCreate(tmp);
}

IO *FileOpen(char *name, bool write_mode)
{
    if (name == NULL) return NULL;

    int flags = write_mode ? O_RDWR : O_RDONLY;
    int fd = open(name, flags);
    if (fd < 0) return NULL;

    IO *io = Malloc(sizeof(IO));
    io->fd = fd;
    io->Name = CopyStr(name);
    io->WriteMode = write_mode;
    io->HamMode = false;

    return io;
}

IO *FileOpenW(wchar_t *name, bool write_mode)
{
    if (name == NULL) return NULL;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return FileOpen(tmp, write_mode);
}

void FileClose(IO *io, bool no_flush)
{
    (void)no_flush;
    if (io == NULL) return;

    close(io->fd);
    Free(io->Name);
    Free(io);
}

UINT FileRead(IO *io, void *buf, UINT size)
{
    if (io == NULL || buf == NULL) return 0;
    return (UINT)read(io->fd, buf, size);
}

UINT FileWrite(IO *io, void *buf, UINT size)
{
    if (io == NULL || buf == NULL) return 0;
    return (UINT)write(io->fd, buf, size);
}

UINT64 FileSize64(IO *io)
{
    if (io == NULL) return 0;
    struct stat st;
    if (fstat(io->fd, &st) != 0) return 0;
    return (UINT64)st.st_size;
}

bool FileSeek(IO *io, UINT64 offset, int mode)
{
    if (io == NULL) return false;
    int whence;
    switch (mode)
    {
    case SEEK_SET: whence = SEEK_SET; break;
    case SEEK_CUR: whence = SEEK_CUR; break;
    case SEEK_END: whence = SEEK_END; break;
    default: return false;
    }
    return (lseek(io->fd, (off_t)offset, whence) >= 0);
}

UINT64 FilePosition(IO *io)
{
    if (io == NULL) return 0;
    return (UINT64)lseek(io->fd, 0, SEEK_CUR);
}

bool FileFlush(IO *io)
{
    if (io == NULL) return false;
    return (fsync(io->fd) == 0);
}

// Enum directory
DIRLIST *EnumDir(char *name)
{
    if (name == NULL) return NULL;

    DIR *dir = opendir(name);
    if (dir == NULL) return NULL;

    DIRLIST *ret = Malloc(sizeof(DIRLIST));
    ret->NumFiles = 0;
    ret->File = NULL;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (StrCmp(entry->d_name, ".") == 0 || StrCmp(entry->d_name, "..") == 0)
            continue;

        ret->NumFiles++;
        ret->File = ReAlloc(ret->File, sizeof(DIRENT) * ret->NumFiles);
        DIRENT *e = &ret->File[ret->NumFiles - 1];

        Zero(e, sizeof(DIRENT));
        StrCpy(e->FileName, sizeof(e->FileName), entry->d_name);
        e->Folder = (entry->d_type == DT_DIR);
    }

    closedir(dir);
    return ret;
}

DIRLIST *EnumDirW(wchar_t *name)
{
    if (name == NULL) return NULL;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), name);
    return EnumDir(tmp);
}

void FreeDir(DIRLIST *d)
{
    if (d == NULL) return;
    Free(d->File);
    Free(d);
}

// Path operations
void GetDirNameFromFilePath(char *dst, UINT size, char *src)
{
    if (dst == NULL || size == 0) return;

    char tmp[MAX_PATH];
    StrCpy(tmp, sizeof(tmp), src);

    char *p = strrchr(tmp, '/');
    if (p != NULL && p != tmp)
    {
        *p = 0;
        StrCpy(dst, size, tmp);
    }
    else
    {
        StrCpy(dst, size, "/");
    }
}

void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *src)
{
    if (dst == NULL || size == 0) return;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), src);
    char result[MAX_PATH];
    GetDirNameFromFilePath(result, sizeof(result), tmp);
    StrToUni(dst, size, result);
}

void GetFileNameFromFilePath(char *dst, UINT size, char *src)
{
    if (dst == NULL || size == 0) return;

    char *p = strrchr(src, '/');
    if (p != NULL)
    {
        StrCpy(dst, size, p + 1);
    }
    else
    {
        StrCpy(dst, size, src);
    }
}

void GetFileNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *src)
{
    if (dst == NULL || size == 0) return;
    char tmp[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), src);
    char result[MAX_PATH];
    GetFileNameFromFilePath(result, sizeof(result), tmp);
    StrToUni(dst, size, result);
}

void CombinePath(char *dst, UINT size, char *dir, char *file)
{
    if (dst == NULL || size == 0) return;

    if (dir == NULL || file == NULL)
    {
        StrCpy(dst, size, "");
        return;
    }

    if (EndWith(dir, "/"))
    {
        Format(dst, size, "%s%s", dir, file);
    }
    else
    {
        Format(dst, size, "%s/%s", dir, file);
    }
}

void CombinePathW(wchar_t *dst, UINT size, wchar_t *dir, wchar_t *file)
{
    if (dst == NULL || size == 0) return;
    char d[MAX_PATH], f[MAX_PATH], r[MAX_PATH];
    UniToStr(d, sizeof(d), dir);
    UniToStr(f, sizeof(f), file);
    CombinePath(r, sizeof(r), d, f);
    StrToUni(dst, size, r);
}

void NormalizePath(char *dst, UINT size, char *src)
{
    if (dst == NULL || size == 0) return;
    if (src == NULL)
    {
        StrCpy(dst, size, "");
        return;
    }

    // Remove redundant slashes
    char tmp[MAX_PATH];
    UINT j = 0;
    for (UINT i = 0; src[i] && j < sizeof(tmp) - 1; i++)
    {
        if (src[i] == '/' && i > 0 && src[i-1] == '/')
            continue;
        tmp[j++] = src[i];
    }
    tmp[j] = 0;

    StrCpy(dst, size, tmp);
}

void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src)
{
    if (dst == NULL || size == 0) return;
    char tmp[MAX_PATH], result[MAX_PATH];
    UniToStr(tmp, sizeof(tmp), src);
    NormalizePath(result, sizeof(result), tmp);
    StrToUni(dst, size, result);
}

// Concurrency file lock
void ConcurrencyCheckInit()
{
}

void ConcurrencyCheckUninit()
{
}

void ConcurrencyCheck()
{
}
