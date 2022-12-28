#include <yara/endian.h>
#include <yara/modules.h>

#define MODULE_NAME ole

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint16_t WCHAR;
typedef int16_t SHORT;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint64_t ULONGLONG;

// https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
typedef struct _GUID
{
  unsigned long Data1;
  unsigned short Data2;
  unsigned short Data3;
  unsigned char Data4[8];
} GUID, *PGUID;

bool NullGuid(PGUID pGuid)
{
  return pGuid != NULL && pGuid->Data1 == 0 && pGuid->Data2 == 0 &&
         pGuid->Data3 == 0 && (ULONGLONG) pGuid->Data4 == 0;
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/9d33df18-7aee-4065-9121-4eabe41c29d4
#define MAXREGSECT 0xFFFFFFFA
#define DIFSECT    0xFFFFFFFC
#define FATSECT    0xFFFFFFFD
#define ENDOFCHAIN 0xFFFFFFFE
#define FREESECT   0xFFFFFFFF

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
typedef struct _COMPOUND_FILE_HEADER
{
  ULONGLONG header_signature;
  GUID header_clsid;
  WORD version_minor;
  WORD version_major;
  WORD byte_order;
  WORD sector_shift;
  WORD mini_sector_shift;
  BYTE reserved[6];
  DWORD number_of_directory_sectors;
  DWORD number_of_fat_sectors;
  DWORD first_directory_sector_location;
  DWORD transaction_signature_number;
  DWORD mini_stream_cutoff_size;
  DWORD first_mini_fat_sector_location;
  DWORD number_of_mini_fat_sectors;
  DWORD first_difat_sector_location;
  DWORD number_of_difat_sectors;
  ULONG difat[109];
  DWORD unused_5;
  DWORD unused_6;
} COMPOUND_FILE_HEADER, *PCOMPOUND_FILE_HEADER;

#define HEADER_SIGNATURE 0xE11AB1A1E011CFD0

#define VERSION_3_MINOR 0x003E
#define VERSION_4_MINOR 0x003E

#define VERSION_3_MAJOR 0x0003
#define VERSION_4_MAJOR 0x0004

#define BYTE_ORDER_LITTLE_ENDIAN 0xFFFE

#define SECTOR_SHIFT_VERSION_3 0x0009
#define SECTOR_SHIFT_VERSION_4 0x000C

#define SECTOR_SIZE_VERSION_3 1 << SECTOR_SHIFT_VERSION_3
#define SECTOR_SIZE_VERSION_4 1 << SECTOR_SHIFT_VERSION_4

#define MINI_SECTOR_SHIFT 0x0006

#define MINI_SECTOR_SIZE 1 << MINI_SECTOR_SHIFT

#define NUMBER_OF_DIRECTORY_SECTORS_VERSION_3 0x00000000

#define MINI_STREAM_CUTOFF_SIZE 0x00001000

begin_declarations
  declare_integer("is_ole");
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  const uint8_t* block_data = NULL;
  COMPOUND_FILE_HEADER* ole = NULL;

  yr_set_integer(0, module_object, "is_ole");

  foreach_memory_block(iterator, block)
  {
    block_data = block->fetch_data(block);

    if (block_data == NULL || block->size < sizeof(COMPOUND_FILE_HEADER))
      continue;

    ole = (PCOMPOUND_FILE_HEADER) block_data;

    if (yr_le64toh(ole->header_signature) != HEADER_SIGNATURE)
      continue;

    yr_set_integer(1, module_object, "is_ole");

    break;
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
