// Path: rufus.c
/*
 * Rufus MR: The Reliable USB Formatting Utility

Copyright © 2011-2022 Max Regner

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#lets make the code
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "rufus.h"
#include "resource.h"
#include "msapi_utf8.h"
#include "localization.h"
#include "drive.h"
#include "file.h"
#include "registry.h"
#include "settings.h"
#include "list.h"
#include "format.h"
#include "boot.h"
#include "fat32format.h"
#include "ntfsformat.h"
#include "iso.h"
#include "image.h"
#include "partition.h"
#include "process.h"
#include "msapi_utf8.h"
#include "win32.h"
#include "gui.h"

// Path: rufus.c
static void rufus_init(void)
{
	// Init the MS API
	msapi_init();

	// Init the localization
	init_localization();

	// Init the settings
	init_settings();

	// Init the drive list
	init_drives();

	// Init the ISO list
	init_iso_list();

	// Init the image list
	init_image_list();

	// Init the GUI
	init_gui();

	// Init the boot selection
	init_boot();

	// Init the process
	init_process();

	// Init the log
	init_log();
}

static void rufus_exit(void)
{
	// Exit the process
	exit_process();

	// Exit the GUI
	exit_gui();

	// Exit the image list
	exit_image_list();

	// Exit the ISO list
	exit_iso_list();

	// Exit the drive list
	exit_drives();

	// Exit the settings
	exit_settings();

	// Exit the localization
	exit_localization();

	// Exit the MS API
	msapi_exit();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	// Init the app
	rufus_init();

	// Run the app
	run_gui();

	// Exit the app
	rufus_exit();

	return 0;
}

// Path: rufus.h
#pragma once
#include <windows.h>
#include <malloc.h>
#include <inttypes.h>

// Path: rufus.h
// This is the size of the buffer used for file and device I/O
#define BUFFER_SIZE (64*1024)

// Path: rufus.h
// This is the size of the buffer used for file and device I/O
#define BUFFER_SIZE (64*1024)

// Path: rufus.h
// This is the size of the buffer used for file and device I/O
#define BUFFER_SIZE (64*1024)

// Path: rufus.h
// This is the size of the buffer used for file and device I/O
#define BUFFER_SIZE (64*1024)

/* Special handling for old .c32 files we need to replace */
#define NB_OLD_C32          2
#define OLD_C32_NAMES       { "menu.c32", "vesamenu.c32" }
#define OLD_C32_THRESHOLD   { 53500, 148000 }

/* ISO details that the application may want */
#define WINPE_I386          0x0007
#define WINPE_AMD64         0x0023
#define WINPE_MININT        0x01C0
#define SPECIAL_WIM_VERSION 0x000E0000
#define HAS_KOLIBRIOS(r)    (r.has_kolibrios)
#define HAS_REACTOS(r)      (r.reactos_path[0] != 0)
#define HAS_GRUB(r)         ((r.has_grub2) || (r.has_grub4dos))
#define HAS_SYSLINUX(r)     (r.sl_version != 0)
#define HAS_BOOTMGR_BIOS(r) (r.has_bootmgr)
#define HAS_BOOTMGR_EFI(r)  (r.has_bootmgr_efi)
#define HAS_BOOTMGR(r)      (HAS_BOOTMGR_BIOS(r) || HAS_BOOTMGR_EFI(r))
#define HAS_REGULAR_EFI(r)  (r.has_efi & 0x7FFE)
#define HAS_WININST(r)      (r.wininst_index != 0)
#define HAS_WINPE(r)        (((r.winpe & WINPE_I386) == WINPE_I386)||((r.winpe & WINPE_AMD64) == WINPE_AMD64)||((r.winpe & WINPE_MININT) == WINPE_MININT))
#define HAS_WINDOWS(r)      (HAS_BOOTMGR(r) || (r.uses_minint) || HAS_WINPE(r))
#define HAS_WIN7_EFI(r)     ((r.has_efi == 1) && HAS_WININST(r))
#define IS_WINDOWS_1X(r)    (r.has_bootmgr_efi && (r.win_version.major >= 10))
#define IS_WINDOWS_11(r)    (r.has_bootmgr_efi && (r.win_version.major >= 11))
#define HAS_EFI_IMG(r)      (r.efi_img_path[0] != 0)
#define IS_DD_BOOTABLE(r)   (r.is_bootable_img > 0)
#define IS_DD_ONLY(r)       ((r.is_bootable_img > 0) && (!r.is_iso || r.disable_iso))
#define IS_EFI_BOOTABLE(r)  (r.has_efi != 0)
#define IS_BIOS_BOOTABLE(r) (HAS_BOOTMGR(r) || HAS_SYSLINUX(r) || HAS_WINPE(r) || HAS_GRUB(r) || HAS_REACTOS(r) || HAS_KOLIBRIOS(r))
#define HAS_WINTOGO(r)      (HAS_BOOTMGR(r) && IS_EFI_BOOTABLE(r) && HAS_WININST(r))
#define HAS_PERSISTENCE(r)  ((HAS_SYSLINUX(r) || HAS_GRUB(r)) && !(HAS_WINDOWS(r) || HAS_REACTOS(r) || HAS_KOLIBRIOS(r)))
#define IS_FAT(fs)          ((fs == FS_FAT16) || (fs == FS_FAT32))
#define IS_EXT(fs)          ((fs >= FS_EXT2) && (fs <= FS_EXT4))
#define SYMLINKS_RR         0x01
#define SYMLINKS_UDF        0x02

typedef struct {
	uint16_t major;
	uint16_t minor;
	uint16_t build;
	uint16_t revision;
} winver_t;

typedef struct {
	char label[192];					// 3*64 to account for UTF-8
	char usb_label[192];				// converted USB label for workaround
	char cfg_path[128];					// path to the ISO's isolinux.cfg
	char reactos_path[128];				// path to the ISO's freeldr.sys or setupldr.sys
	char wininst_path[MAX_WININST][64];	// path to the Windows install image(s)
	char efi_img_path[128];				// path to an efi.img file
	uint64_t image_size;
	uint64_t archive_size;
	uint64_t projected_size;
	int64_t mismatch_size;
	uint32_t wininst_version;
	BOOLEAN is_iso;
	int8_t is_bootable_img;
	BOOLEAN is_vhd;
	BOOLEAN is_windows_img;
	BOOLEAN disable_iso;
	BOOLEAN rh8_derivative;
	uint16_t winpe;
	uint16_t has_efi;
	uint8_t has_md5sum;
	uint8_t wininst_index;
	uint8_t has_symlinks;
	BOOLEAN has_4GB_file;
	BOOLEAN has_long_filename;
	BOOLEAN has_deep_directories;
	BOOLEAN has_bootmgr;
	BOOLEAN has_bootmgr_efi;
	BOOLEAN has_autorun;
	BOOLEAN has_old_c32[NB_OLD_C32];
	BOOLEAN has_old_vesamenu;
	BOOLEAN has_efi_syslinux;
	BOOLEAN needs_syslinux_overwrite;
	BOOLEAN has_grub4dos;
	uint8_t has_grub2;
	BOOLEAN has_compatresources_dll;
	BOOLEAN has_kolibrios;
	BOOLEAN uses_casper;
	BOOLEAN uses_minint;
	uint8_t compression_type;
	winver_t win_version;	// Windows ISO version
	uint16_t sl_version;	// Syslinux/Isolinux version
	char sl_version_str[12];
	char sl_version_ext[32];
	char grub2_version[64];
} RUFUS_IMG_REPORT;

/* Isolate the Syslinux version numbers */
#define SL_MAJOR(x) ((uint8_t)((x)>>8))
#define SL_MINOR(x) ((uint8_t)(x))

typedef struct {
	char* id;
	char* name;
	char* display_name;
	char* label;
	char* hub;
	DWORD index;
	uint32_t port;
	uint64_t size;
} RUFUS_DRIVE;

typedef struct {
	uint16_t version[3];
	uint32_t platform_min[2];		// minimum platform version required
	char* download_url;
	char* release_notes;
} RUFUS_UPDATE;

#define IMG_SAVE_TYPE_VHD 1
#define IMG_SAVE_TYPE_ISO 2

typedef struct {
	DWORD Type;
	DWORD DeviceNum;
	DWORD BufSize;
	LONGLONG DeviceSize;
	char* DevicePath;
	char* ImagePath;
	char* Label;
} IMG_SAVE;

/*
 * Structure and macros used for the extensions specification of FileDialog()
 * You can use:
 *   EXT_DECL(my_extensions, "default.std", __VA_GROUP__("*.std", "*.other"), __VA_GROUP__("Standard type", "Other Type"));
 * to define an 'ext_t my_extensions' variable initialized with the relevant attributes.
 */
typedef struct ext_t {
	const size_t count;
	const char* filename;
	const char** extension;
	const char** description;
} ext_t;

#ifndef __VA_GROUP__
#define __VA_GROUP__(...)  __VA_ARGS__
#endif
#define EXT_X(prefix, ...) const char* _##prefix##_x[] = { __VA_ARGS__ }
#define EXT_D(prefix, ...) const char* _##prefix##_d[] = { __VA_ARGS__ }
#define EXT_DECL(var, filename, extensions, descriptions)                   \
	EXT_X(var, extensions);                                                 \
	EXT_D(var, descriptions);                                               \
	ext_t var = { ARRAYSIZE(_##var##_x), filename, _##var##_x, _##var##_d }

/* Duplication of the TBPFLAG enum for Windows 7 taskbar progress */
typedef enum TASKBAR_PROGRESS_FLAGS
{
	TASKBAR_NOPROGRESS = 0,
	TASKBAR_INDETERMINATE = 0x1,
	TASKBAR_NORMAL = 0x2,
	TASKBAR_ERROR = 0x4,
	TASKBAR_PAUSED = 0x8
} TASKBAR_PROGRESS_FLAGS;

/* Windows versions */
enum WindowsVersion {
	WINDOWS_UNDEFINED = -1,
	WINDOWS_UNSUPPORTED = 0,
	WINDOWS_XP = 0x51,
	WINDOWS_2003 = 0x52,	// Also XP_64
	WINDOWS_VISTA = 0x60,	// Also Server 2008
	WINDOWS_7 = 0x61,		// Also Server 2008_R2
	WINDOWS_8 = 0x62,		// Also Server 2012
	WINDOWS_8_1 = 0x63,		// Also Server 2012_R2
	WINDOWS_10_PREVIEW1 = 0x64,
	WINDOWS_10 = 0xA0,		// Also Server 2016, also Server 2019
	WINDOWS_11 = 0xB0,		// Also Server 2022
	WINDOWS_MAX
};

enum ArchType {
	ARCH_UNKNOWN = 0,
	ARCH_X86_32,
	ARCH_X86_64,
	ARCH_ARM_32,
	ARCH_ARM_64,
	ARCH_IA_64,
	ARCH_RISCV_32,
	ARCH_RISCV_64,
	ARCH_RISCV_128,
	ARCH_EBC,
	ARCH_MAX
};

// Windows User Experience (unattend.xml) flags and masks
#define UNATTEND_SECUREBOOT_TPM_MINRAM      0x00001
#define UNATTEND_NO_ONLINE_ACCOUNT          0x00004
#define UNATTEND_NO_DATA_COLLECTION         0x00008
#define UNATTEND_OFFLINE_INTERNAL_DRIVES    0x00010
#define UNATTEND_DUPLICATE_LOCALE           0x00020
#define UNATTEND_SET_USER                   0x00040
#define UNATTEND_DEFAULT_MASK               0x0007F
#define UNATTEND_WINDOWS_TO_GO              0x10000		// Special flag for Windows To Go

#define UNATTEND_WINPE_SETUP_MASK           (UNATTEND_SECUREBOOT_TPM_MINRAM)
#define UNATTEND_SPECIALIZE_DEPLOYMENT_MASK (UNATTEND_NO_ONLINE_ACCOUNT)
#define UNATTEND_OOBE_SHELL_SETUP_MASK      (UNATTEND_NO_DATA_COLLECTION | UNATTEND_SET_USER)
#define UNATTEND_OOBE_INTERNATIONAL_MASK    (UNATTEND_DUPLICATE_LOCALE)
#define UNATTEND_OOBE_MASK                  (UNATTEND_OOBE_SHELL_SETUP_MASK | UNATTEND_OOBE_INTERNATIONAL_MASK)
#define UNATTEND_OFFLINE_SERVICING_MASK     (UNATTEND_OFFLINE_INTERNAL_DRIVES)
#define UNATTEND_DEFAULT_SELECTION_MASK     (UNATTEND_SECUREBOOT_TPM_MINRAM | UNATTEND_NO_ONLINE_ACCOUNT | UNATTEND_OFFLINE_INTERNAL_DRIVES)

/*
 * Globals
 */
extern RUFUS_UPDATE update;
extern RUFUS_IMG_REPORT img_report;
extern HINSTANCE hMainInstance;
extern HWND hMainDialog, hLogDialog, hStatus, hDeviceList, hCapacity, hImageOption;
extern HWND hPartitionScheme, hTargetSystem, hFileSystem, hClusterSize, hLabel, hBootType, hNBPasses, hLog;
extern HWND hInfo, hProgress, hDiskID;
extern WORD selected_langid;
extern DWORD FormatStatus, DownloadStatus, MainThreadId, LastWriteError;
extern BOOL use_own_c32[NB_OLD_C32], detect_fakes, op_in_progress, right_to_left_mode;
extern BOOL allow_dual_uefi_bios, large_drive, usb_debug;
extern int64_t iso_blocking_status;
extern uint8_t image_options;
extern uint16_t rufus_version[3], embedded_sl_version[2];
extern uint64_t persistence_size;
extern size_t ubuffer_pos;
extern const int nb_steps[FS_MAX];
extern float fScale;
extern int nWindowsVersion, nWindowsBuildNumber, nWindowsEdition, dialog_showing, force_update;
extern int fs_type, boot_type, partition_type, target_type;
extern unsigned long syslinux_ldlinux_len[2];
extern char WindowsVersionStr[128], ubuffer[UBUFFER_SIZE], embedded_sl_version_str[2][12];
extern char szFolderPath[MAX_PATH], app_dir[MAX_PATH], temp_dir[MAX_PATH], system_dir[MAX_PATH], sysnative_dir[MAX_PATH];
extern char app_data_dir[MAX_PATH], *image_path, *fido_url;

/*
 * Shared prototypes
 */
extern void GetWindowsVersion(void);
extern BOOL is_x64(void);
extern int GetCpuArch(void);
extern const char *WindowsErrorString(void);
extern void DumpBufferHex(void *buf, size_t size);
extern void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...);
#define PrintStatus(...) PrintStatusInfo(FALSE, FALSE, __VA_ARGS__)
#define PrintStatusDebug(...) PrintStatusInfo(FALSE, TRUE, __VA_ARGS__)
#define PrintInfo(...) PrintStatusInfo(TRUE, FALSE, __VA_ARGS__)
#define PrintInfoDebug(...) PrintStatusInfo(TRUE, TRUE, __VA_ARGS__)
extern void UpdateProgress(int op, float percent);
extern void _UpdateProgressWithInfo(int op, int msg, uint64_t processed, uint64_t total, BOOL force);
#define UpdateProgressWithInfo(op, msg, processed, total) _UpdateProgressWithInfo(op, msg, processed, total, FALSE)
#define UpdateProgressWithInfoForce(op, msg, processed, total) _UpdateProgressWithInfo(op, msg, processed, total, TRUE)
#define UpdateProgressWithInfoInit(hProgressDialog, bNoAltMode) UpdateProgressWithInfo(OP_INIT, (int)bNoAltMode, (uint64_t)(uintptr_t)hProgressDialog, 0);
extern const char* StrError(DWORD error_code, BOOL use_default_locale);
extern char* GuidToString(const GUID* guid);
extern GUID* StringToGuid(const char* str);
extern char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units);
extern char* TimestampToHumanReadable(uint64_t ts);
extern HWND MyCreateDialog(HINSTANCE hInstance, int Dialog_ID, HWND hWndParent, DLGPROC lpDialogFunc);
extern INT_PTR MyDialogBox(HINSTANCE hInstance, int Dialog_ID, HWND hWndParent, DLGPROC lpDialogFunc);
extern void CenterDialog(HWND hDlg, HWND hParent);
extern void ResizeMoveCtrl(HWND hDlg, HWND hCtrl, int dx, int dy, int dw, int dh, float scale);
extern void ResizeButtonHeight(HWND hDlg, int id);
extern void CreateStatusBar(void);
extern void CreateStaticFont(HDC hDC, HFONT* hFont, BOOL underlined);
extern void SetTitleBarIcon(HWND hDlg);
extern BOOL CreateTaskbarList(void);
extern BOOL SetTaskbarProgressState(TASKBAR_PROGRESS_FLAGS tbpFlags);
extern BOOL SetTaskbarProgressValue(ULONGLONG ullCompleted, ULONGLONG ullTotal);
extern INT_PTR CreateAboutBox(void);
extern BOOL CreateTooltip(HWND hControl, const char* message, int duration);
extern void DestroyTooltip(HWND hWnd);
extern void DestroyAllTooltips(void);
extern BOOL Notification(int type, const char* dont_display_setting, const notification_info* more_info, char* title, char* format, ...);
extern int CustomSelectionDialog(int style, char* title, char* message, char** choices, int size, int mask, int username_index);
#define SelectionDialog(title, message, choices, size) CustomSelectionDialog(BS_AUTORADIOBUTTON, title, message, choices, size, 1, -1)
extern void ListDialog(char* title, char* message, char** items, int size);
extern SIZE GetTextSize(HWND hCtrl, char* txt);
extern BOOL ExtractAppIcon(const char* filename, BOOL bSilent);
extern BOOL ExtractDOS(const char* path);
extern BOOL ExtractISO(const char* src_iso, const char* dest_dir, BOOL scan);
extern int64_t ExtractISOFile(const char* iso, const char* iso_file, const char* dest_file, DWORD attributes);
extern BOOL HasEfiImgBootLoaders(void);
extern BOOL DumpFatDir(const char* path, int32_t cluster);
extern char* MountISO(const char* path);
extern void UnMountISO(void);
extern BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int fs);
extern uint16_t GetSyslinuxVersion(char* buf, size_t buf_size, char** ext);
extern BOOL SetAutorun(const char* path);
extern char* FileDialog(BOOL save, char* path, const ext_t* ext, DWORD options);
extern BOOL FileIO(BOOL save, char* path, char** buffer, DWORD* size);
extern unsigned char* GetResource(HMODULE module, char* name, char* type, const char* desc, DWORD* len, BOOL duplicate);
extern DWORD GetResourceSize(HMODULE module, char* name, char* type, const char* desc);
extern DWORD RunCommand(const char* cmdline, const char* dir, BOOL log);
extern BOOL CompareGUID(const GUID *guid1, const GUID *guid2);
extern BOOL MountRegistryHive(const HKEY key, const char* pszHiveName, const char* pszHivePath);
extern BOOL UnmountRegistryHive(const HKEY key, const char* pszHiveName);
extern BOOL SetLGP(BOOL bRestore, BOOL* bExistingKey, const char* szPath, const char* szPolicy, DWORD dwValue);
extern LONG GetEntryWidth(HWND hDropDown, const char* entry);
extern uint64_t DownloadToFileOrBuffer(const char* url, const char* file, BYTE** buffer, HWND hProgressDialog, BOOL bTaskBarProgress);
extern DWORD DownloadSignedFile(const char* url, const char* file, HWND hProgressDialog, BOOL PromptOnError);
extern HANDLE DownloadSignedFileThreaded(const char* url, const char* file, HWND hProgressDialog, BOOL bPromptOnError);
extern INT_PTR CALLBACK UpdateCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
extern void SetFidoCheck(void);
extern BOOL SetUpdateCheck(void);
extern BOOL CheckForUpdates(BOOL force);
extern void DownloadNewVersion(void);
extern BOOL DownloadISO(void);
extern BOOL IsDownloadable(const char* url);
extern BOOL IsShown(HWND hDlg);
extern uint32_t read_file(const char* path, uint8_t** buf);
extern uint32_t write_file(const char* path, const uint8_t* buf, const uint32_t size);
extern char* get_token_data_file_indexed(const char* token, const char* filename, int index);
#define get_token_data_file(token, filename) get_token_data_file_indexed(token, filename, 1)
extern char* set_token_data_file(const char* token, const char* data, const char* filename);
extern char* get_token_data_buffer(const char* token, unsigned int n, const char* buffer, size_t buffer_size);
extern char* insert_section_data(const char* filename, const char* section, const char* data, BOOL dos2unix);
extern char* replace_in_token_data(const char* filename, const char* token, const char* src, const char* rep, BOOL dos2unix);
extern char* replace_char(const char* src, const char c, const char* rep);
extern void parse_update(char* buf, size_t len);
extern void* get_data_from_asn1(const uint8_t* buf, size_t buf_len, const char* oid_str, uint8_t asn1_type, size_t* data_len);
extern int IsHDD(DWORD DriveIndex, uint16_t vid, uint16_t pid, const char* strid);
extern char* GetSignatureName(const char* path, const char* country_code, BOOL bSilent);
extern uint64_t GetSignatureTimeStamp(const char* path);
extern LONG ValidateSignature(HWND hDlg, const char* path);
extern BOOL ValidateOpensslSignature(BYTE* pbBuffer, DWORD dwBufferLen, BYTE* pbSignature, DWORD dwSigLen);
extern BOOL IsFontAvailable(const char* font_name);
extern BOOL WriteFileWithRetry(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten, DWORD nNumRetries);
extern BOOL SetThreadAffinity(DWORD_PTR* thread_affinity, size_t num_threads);
extern BOOL HashFile(const unsigned type, const char* path, uint8_t* sum);
extern BOOL HashBuffer(const unsigned type, const uint8_t* buf, const size_t len, uint8_t* sum);
extern BOOL IsFileInDB(const char* path);
extern BOOL IsBufferInDB(const unsigned char* buf, const size_t len);
#define printbits(x) _printbits(sizeof(x), &x, 0)
#define printbitslz(x) _printbits(sizeof(x), &x, 1)
extern char* _printbits(size_t const size, void const * const ptr, int leading_zeroes);
extern BOOL IsCurrentProcessElevated(void);
extern char* ToLocaleName(DWORD lang_id);
extern void SetAlertPromptMessages(void);
extern BOOL SetAlertPromptHook(void);
extern void ClrAlertPromptHook(void);
extern DWORD CheckDriveAccess(DWORD dwTimeOut, BOOL bPrompt);
extern BYTE SearchProcess(char* HandleName, DWORD dwTimeout, BOOL bPartialMatch, BOOL bIgnoreSelf, BOOL bQuiet);
extern BOOL EnablePrivileges(void);
extern void FlashTaskbar(HANDLE handle);
extern DWORD WaitForSingleObjectWithMessages(HANDLE hHandle, DWORD dwMilliseconds);
extern HICON CreateMirroredIcon(HICON hiconOrg);
extern HANDLE CreatePreallocatedFile(const char* lpFileName, DWORD dwDesiredAccess,
	DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, LONGLONG fileSize);
#define GetTextWidth(hDlg, id) GetTextSize(GetDlgItem(hDlg, id), NULL).cx

DWORD WINAPI SaveImageThread(void* param);
DWORD WINAPI SumThread(void* param);

/* Hash tables */
typedef struct htab_entry {
	uint32_t used;
	char* str;
	void* data;
} htab_entry;
typedef struct htab_table {
	htab_entry *table;
	uint32_t size;
	uint32_t filled;
} htab_table;
#define HTAB_EMPTY {NULL, 0, 0}
extern BOOL htab_create(uint32_t nel, htab_table* htab);
extern void htab_destroy(htab_table* htab);
extern uint32_t htab_hash(char* str, htab_table* htab);

/* Basic String Array */
typedef struct {
	char**   String;
	uint32_t Index;		// Current array size
	uint32_t Max;		// Maximum array size
} StrArray;
extern void StrArrayCreate(StrArray* arr, uint32_t initial_size);
extern int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL );
extern int32_t StrArrayFind(StrArray* arr, const char* str);
extern void StrArrayClear(StrArray* arr);
extern void StrArrayDestroy(StrArray* arr);
#define IsStrArrayEmpty(arr) (arr.Index == 0)

/*
 * typedefs for the function prototypes. Use the something like:
 *   PF_DECL(FormatEx);
 * which translates to:
 *   FormatEx_t pfFormatEx = NULL;
 * in your code, to declare the entrypoint and then use:
 *   PF_INIT(FormatEx, Fmifs);
 * which translates to:
 *   pfFormatEx = (FormatEx_t) GetProcAddress(GetDLLHandle("fmifs"), "FormatEx");
 * to make it accessible.
 */
#define         MAX_LIBRARY_HANDLES 64
extern HMODULE  OpenedLibrariesHandle[MAX_LIBRARY_HANDLES];
extern uint16_t OpenedLibrariesHandleSize;
#define         OPENED_LIBRARIES_VARS HMODULE OpenedLibrariesHandle[MAX_LIBRARY_HANDLES]; uint16_t OpenedLibrariesHandleSize = 0
#define         CLOSE_OPENED_LIBRARIES while(OpenedLibrariesHandleSize > 0) FreeLibrary(OpenedLibrariesHandle[--OpenedLibrariesHandleSize])
static __inline HMODULE GetLibraryHandle(char* szLibraryName) {
	HMODULE h = NULL;
	wchar_t* wszLibraryName = NULL;
	int size;
	if (szLibraryName == NULL || szLibraryName[0] == 0)
		goto out;
	size = MultiByteToWideChar(CP_UTF8, 0, szLibraryName, -1, NULL, 0);
	if ((size <= 1) || ((wszLibraryName = (wchar_t*)calloc(size, sizeof(wchar_t))) == NULL) ||
		(MultiByteToWideChar(CP_UTF8, 0, szLibraryName, -1, wszLibraryName, size) != size))
		goto out;
	// If the library is already opened, just return a handle (that doesn't need to be freed)
	if ((h = GetModuleHandleW(wszLibraryName)) != NULL)
		goto out;
	// Sanity check
	if (OpenedLibrariesHandleSize >= MAX_LIBRARY_HANDLES) {
		uprintf("Error: MAX_LIBRARY_HANDLES is too small\n");
		goto out;
	}
	h = LoadLibraryExW(wszLibraryName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	// Some Windows 7 platforms (most likely the ones missing KB2533623 per the
	// official LoadLibraryEx doc) can return ERROR_INVALID_PARAMETER when using
	// the Ex() version. If that's the case, fallback to using LoadLibraryW().
	if ((h == NULL) && (SCODE_CODE(GetLastError()) == ERROR_INVALID_PARAMETER))
		h = LoadLibraryW(wszLibraryName);
	if (h != NULL)
		OpenedLibrariesHandle[OpenedLibrariesHandleSize++] = h;
	else
		uprintf("Unable to load '%S.dll': %s", wszLibraryName, WindowsErrorString());
out:
	free(wszLibraryName);
	return h;
}
#define PF_TYPE(api, ret, proc, args)		typedef ret (api *proc##_t)args
#define PF_DECL(proc)						static proc##_t pf##proc = NULL
#define PF_TYPE_DECL(api, ret, proc, args)	PF_TYPE(api, ret, proc, args); PF_DECL(proc)
#define PF_INIT(proc, name)					if (pf##proc == NULL) pf##proc = \
	(proc##_t) GetProcAddress(GetLibraryHandle(#name), #proc)
#define PF_INIT_OR_OUT(proc, name)			do {PF_INIT(proc, name);         \
	if (pf##proc == NULL) {uprintf("Unable to locate %s() in '%s.dll': %s",  \
	#proc, #name, WindowsErrorString()); goto out;} } while(0)
#define PF_INIT_OR_SET_STATUS(proc, name)	do {PF_INIT(proc, name);         \
	if ((pf##proc == NULL) && (NT_SUCCESS(status))) status = STATUS_NOT_IMPLEMENTED; } while(0)

/* Custom application errors */
#define FAC(f)                         ((f)<<16)
#define APPERR(err)                    (APPLICATION_ERROR_MASK|(err))
#define ERROR_INCOMPATIBLE_FS          0x1201
#define ERROR_CANT_QUICK_FORMAT        0x1202
#define ERROR_INVALID_CLUSTER_SIZE     0x1203
#define ERROR_INVALID_VOLUME_SIZE      0x1204
#define ERROR_CANT_START_THREAD        0x1205
#define ERROR_BADBLOCKS_FAILURE        0x1206
#define ERROR_ISO_SCAN                 0x1207
#define ERROR_ISO_EXTRACT              0x1208
#define ERROR_CANT_REMOUNT_VOLUME      0x1209
#define ERROR_CANT_PATCH               0x120A
#define ERROR_CANT_ASSIGN_LETTER       0x120B
#define ERROR_CANT_MOUNT_VOLUME        0x120C
#define ERROR_BAD_SIGNATURE            0x120D
#define ERROR_CANT_DOWNLOAD            0x120E
