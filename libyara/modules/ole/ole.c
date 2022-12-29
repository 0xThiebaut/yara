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
  DWORD Data1;
  WORD Data2;
  WORD Data3;
  ULONGLONG Data4;
} GUID, *PGUID;

// https://learn.microsoft.com/en-us/windows/win32/api/guiddef/nf-guiddef-isequalguid
#define IsEqualGUID(rguid1, rguid2)                                \
  (rguid1.Data1 == rguid2.Data1 && rguid1.Data2 == rguid2.Data2 && \
   rguid1.Data3 == rguid2.Data3 && rguid1.Data4 == rguid2.Data4)

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

const GUID CLSID_NULL = {};

#define VERSION_MINOR 0x003E

#define VERSION_MAJOR_3 0x0003
#define VERSION_MAJOR_4 0x0004

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

    if (ole->header_signature != HEADER_SIGNATURE)
      continue;

    if (!IsEqualGUID(ole->header_clsid, CLSID_NULL))
      continue;

    if (ole->version_minor != VERSION_MINOR ||
        (ole->version_major != VERSION_MAJOR_3 &&
         ole->version_major != VERSION_MAJOR_4))
      continue;

    if (ole->byte_order != BYTE_ORDER_LITTLE_ENDIAN)
      continue;

    if ((ole->version_major == VERSION_MAJOR_3 &&
         ole->sector_shift != SECTOR_SHIFT_VERSION_3) ||
        (ole->version_major == VERSION_MAJOR_4 &&
         ole->sector_shift != SECTOR_SHIFT_VERSION_4))
      continue;

    if (ole->mini_sector_shift != MINI_SECTOR_SHIFT)
      continue;

    if (ole->reserved[0] || ole->reserved[1] || ole->reserved[2] ||
        ole->reserved[3] || ole->reserved[4] || ole->reserved[5])
      continue;

    if (ole->version_major == VERSION_MAJOR_3 &&
        ole->number_of_directory_sectors != 0)
      continue;

    if (ole->mini_stream_cutoff_size != MINI_STREAM_CUTOFF_SIZE)
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
