#include <wchar.h>
#include <yara/endian.h>
#include <yara/modules.h>
#include "yara/mem.h"

#define MODULE_NAME cfb

/**
 * Related types and macros
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/88486fe1-45c8-417a-bc85-bb84bf3c6983
 */

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d7edc080-e499-4219-a837-1bc40b64bb04
typedef uint8_t BYTE;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f8573df3-a44a-4a50-b070-ac4c3aa78e3c
typedef uint16_t USHORT;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7df7c1d5-492c-4db4-a992-5cd9e887c5d7
typedef uint16_t WCHAR;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/262627d8-3418-4627-9218-4ffe110850b2
typedef uint32_t DWORD;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c57d9fba-12ef-4853-b0d5-a6f472b50388
typedef uint64_t ULONGLONG;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/49e490b8-f972-45d6-a3a4-99f924998d97
typedef struct _GUID
{
  DWORD Data1;
  USHORT Data2;
  USHORT Data3;
  BYTE Data4[8];
} GUID, UUID, *PGUID;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
typedef struct _FILETIME
{
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

// https://learn.microsoft.com/en-us/windows/win32/api/guiddef/nf-guiddef-isequalguid
#define IsEqualGUID(rguid1, rguid2)                                        \
  ((rguid1).Data1 == (rguid2).Data1 && (rguid1).Data2 == (rguid2).Data2 && \
   (rguid1).Data3 == (rguid2).Data3 &&                                     \
   (rguid1).Data4[0] == (rguid2).Data4[0] &&                               \
   (rguid1).Data4[1] == (rguid2).Data4[1] &&                               \
   (rguid1).Data4[2] == (rguid2).Data4[2] &&                               \
   (rguid1).Data4[3] == (rguid2).Data4[3] &&                               \
   (rguid1).Data4[4] == (rguid2).Data4[4] &&                               \
   (rguid1).Data4[5] == (rguid2).Data4[5] &&                               \
   (rguid1).Data4[6] == (rguid2).Data4[6] &&                               \
   (rguid1).Data4[7] == (rguid2).Data4[7])

/**
 * Structures
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/28488197-8193-49d7-84d8-dfd692418ccd
 */

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/9d33df18-7aee-4065-9121-4eabe41c29d4
#define SECTOR_NUMBER_MAXREGSECT (DWORD) 0xFFFFFFFA
#define SECTOR_NUMBER_DIFSECT    (DWORD) 0xFFFFFFFC
#define SECTOR_NUMBER_FATSECT    (DWORD) 0xFFFFFFFD
#define SECTOR_NUMBER_ENDOFCHAIN (DWORD) 0xFFFFFFFE
#define SECTOR_NUMBER_FREESECT   (DWORD) 0xFFFFFFFF

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
typedef struct _COMPOUND_FILE_BINARY_HEADER
{
  ULONGLONG signature;
  GUID clsid;
  USHORT version_minor;
  USHORT version_major;
  USHORT byte_order;
  USHORT sector_shift;
  USHORT mini_sector_shift;
  BYTE reserved[6];
  DWORD number_of_directory_sectors;
  DWORD number_of_fat_sectors;
  DWORD first_directory_sector_location;
  DWORD transaction_signature;
  DWORD mini_stream_cutoff_size;
  DWORD first_mini_fat_sector_location;
  DWORD number_of_mini_fat_sectors;
  DWORD first_difat_sector_location;
  DWORD number_of_difat_sectors;
  DWORD difat[109];
} COMPOUND_FILE_BINARY_HEADER, *PCOMPOUND_FILE_BINARY_HEADER;

#define HEADER_SIGNATURE \
  (ULONGLONG) 0xE11AB1A1E011CFD0  // 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1

const GUID CLSID_NULL = {};

#define VERSION_MINOR (USHORT) 0x003E

#define VERSION_MAJOR_3 (USHORT) 0x0003
#define VERSION_MAJOR_4 (USHORT) 0x0004

#define BYTE_ORDER_LITTLE_ENDIAN (USHORT) 0xFFFE

#define SECTOR_SHIFT_VERSION_3 (USHORT) 0x0009
#define SECTOR_SHIFT_VERSION_4 (USHORT) 0x000C

#define SECTOR_SIZE_VERSION_3 1 << SECTOR_SHIFT_VERSION_3
#define SECTOR_SIZE_VERSION_4 1 << SECTOR_SHIFT_VERSION_4

#define MINI_SECTOR_SHIFT (USHORT) 0x0006
#define MINI_SECTOR_SIZE  1 << MINI_SECTOR_SHIFT

#define NUMBER_OF_DIRECTORY_SECTORS_VERSION_3 (DWORD) 0x00000000

#define MINI_STREAM_CUTOFF_SIZE (DWORD) 0x00001000

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/30e1013a-a0ff-4404-9ccf-d75d835ff404
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/c5d235f7-b73c-4ec5-bf8d-5c08306cd023
typedef struct _SECTOR_3
{
  DWORD next_sector_in_chain[128];
} FAT_SECTOR_3, *PFAT_SECTOR_3, MINI_FAT_SECTOR_3, *PMINI_FAT_SECTOR_3;

typedef struct _SECTOR_4
{
  DWORD next_sector_in_chain[1024];
} FAT_SECTOR_4, *PFAT_SECTOR_4, MINI_FAT_SECTOR_4, *PMINI_FAT_SECTOR_4;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/0afa4e43-b18f-432a-9917-4f276eca7a73
typedef struct _DIFAT_SECTOR_3
{
  DWORD fat_sector_location[127];
  DWORD next_difat_sector_location;
} DIFAT_SECTOR_3, *PDIFAT_SECTOR_3;

typedef struct _DIFAT_SECTOR_4
{
  DWORD fat_sector_location[1023];
  DWORD next_difat_sector_location;
} DIFAT_SECTOR_4, *PDIFAT_SECTOR_4;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/60fe8611-66c3-496b-b70d-a504c94c9ace

#define STREAM_NUMBER_MAXREGSID (DWORD) 0xFFFFFFFA
#define STREAM_NUMBER_NOSTREAM  (DWORD) 0xFFFFFFFF

typedef struct _DIRECTORY_ENTRY
{
  BYTE name[32 * 2];
  USHORT name_length;
  BYTE object_type;
  BYTE color_flag;
  DWORD left_sibling_id;
  DWORD right_sibling_id;
  DWORD child_id;
  GUID clsid;
  DWORD state_bits;
  FILETIME creation_time;
  FILETIME modified_time;
  DWORD starting_sector_location;
  ULONGLONG stream_size;
} DIRECTORY_ENTRY, *PDIRECTORY_ENTRY;

#define OBJECT_TYPE_UNKNOWN      0x00
#define OBJECT_TYPE_UNALLOCATED  0x00
#define OBJECT_TYPE_STORAGE      0x01
#define OBJECT_TYPE_STREAM       0x02
#define OBJECT_TYPE_ROOT_STORAGE 0x05

#define COLOR_FLAG_RED   0x00
#define COLOR_FLAG_BLACK 0x01

#define MAX_STREAM_SIZE_VERSION_3 (ULONGLONG) 0x80000000

/**
 * Yara structures, functions and declarations
 */

typedef struct _COMPOUND_FILE_BINARY
{
  PCOMPOUND_FILE_BINARY_HEADER pHeader;
  DWORD dwSize;
  DWORD *pDifatLocations;
  DWORD dwNumberOfDifatLocations;
  DWORD *pDifat;
  DWORD dwNumberOfDifatEntries;
  DWORD *pFat;
  DWORD dwNumberOfFatEntries;
  DWORD *pMiniFatLocations;
  DWORD dwNumberOfMiniFatLocations;
  DWORD *pMiniFat;
  DWORD dwNumberOfMiniFatEntries;
  PDIRECTORY_ENTRY *pDirectories;
  DWORD dwNumberOfDirectoryEntries;

} COMPOUND_FILE_BINARY, *PCOMPOUND_FILE_BINARY;

static bool is_valid_header(PCOMPOUND_FILE_BINARY_HEADER pHeader);

static void cfb_parse_difat(PCOMPOUND_FILE_BINARY pBinary);

static void cfb_parse_fat(PCOMPOUND_FILE_BINARY pBinary);

static void cfb_parse_mini_fat(PCOMPOUND_FILE_BINARY pBinary);

static void cfb_parse_directories(PCOMPOUND_FILE_BINARY pBinary);

static void cfb_expose_constants(YR_OBJECT *module_object);

static void cfb_expose_header(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY_HEADER pHeader);

static void cfb_expose_difat(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY pBinary);

static void cfb_expose_fat(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY pBinary);

static void cfb_expose_mini_fat(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY pBinary);

static void cfb_expose_directories(
    YR_OBJECT *module_object,
    PDIRECTORY_ENTRY *pDirectories,
    DWORD dwNumberOfDirectoryEntries);

static bool cfb_uint8_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint8_t *bOut);

static bool cfb_uint16_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint16_t *uOut);

static bool cfb_uint32_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint32_t *uOut);

static bool cfb_uint64_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint64_t *uOut);

/**
 * Yara Declarations
 */

define_function(uint8_at_directory_offset)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint8_t n = 0;

  return_integer(
      cfb_uint8_at_directory_offset(pBinary, directory, offset, &n)
          ? n
          : YR_UNDEFINED);
}

define_function(int8_at_directory_offset)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint8_t n = 0;

  return_integer(
      cfb_uint8_at_directory_offset(pBinary, directory, offset, &n)
          ? (int8_t) n
          : YR_UNDEFINED);
}

define_function(uint16_at_directory_offset_le)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint16_t n = 0;

  return_integer(
      cfb_uint16_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_le16toh(n)
          : YR_UNDEFINED);
}

define_function(uint16_at_directory_offset_be)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint16_t n = 0;

  return_integer(
      cfb_uint16_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_be16toh(n)
          : YR_UNDEFINED);
}

define_function(int16_at_directory_offset_le)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint16_t n = 0;

  return_integer(
      cfb_uint16_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_le16toh((int16_t) n)
          : YR_UNDEFINED);
}

define_function(int16_at_directory_offset_be)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint16_t n = 0;

  return_integer(
      cfb_uint16_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_be16toh((int16_t) n)
          : YR_UNDEFINED);
}

define_function(uint32_at_directory_offset_le)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint32_t n = 0;

  return_integer(
      cfb_uint32_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_le32toh(n)
          : YR_UNDEFINED);
}

define_function(uint32_at_directory_offset_be)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint32_t n = 0;

  return_integer(
      cfb_uint32_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_be32toh(n)
          : YR_UNDEFINED);
}

define_function(int32_at_directory_offset_le)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint32_t n = 0;

  return_integer(
      cfb_uint32_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_le32toh((int32_t) n)
          : YR_UNDEFINED);
}

define_function(int32_at_directory_offset_be)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint32_t n = 0;

  return_integer(
      cfb_uint32_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_be32toh((int32_t) n)
          : YR_UNDEFINED);
}

define_function(uint64_at_directory_offset_le)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint64_t n = 0;

  return_integer(
      cfb_uint64_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_le64toh(n)
          : YR_UNDEFINED);
}

define_function(uint64_at_directory_offset_be)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint64_t n = 0;

  return_integer(
      cfb_uint64_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_be64toh(n)
          : YR_UNDEFINED);
}

define_function(int64_at_directory_offset_le)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint64_t n = 0;

  return_integer(
      cfb_uint64_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_le64toh((int64_t) n)
          : YR_UNDEFINED);
}

define_function(int64_at_directory_offset_be)
{
  DWORD directory = (DWORD) integer_argument(1);
  ULONGLONG offset = (ULONGLONG) integer_argument(2);

  PCOMPOUND_FILE_BINARY pBinary = (PCOMPOUND_FILE_BINARY) yr_module()->data;
  uint64_t n = 0;

  return_integer(
      cfb_uint64_at_directory_offset(pBinary, directory, offset, &n)
          ? yr_be64toh((int64_t) n)
          : YR_UNDEFINED);
}

begin_declarations
  declare_integer("is_cfb");

  // Constants
  declare_integer("SECTOR_NUMBER_MAXREGSECT");
  declare_integer("SECTOR_NUMBER_DIFSECT");
  declare_integer("SECTOR_NUMBER_FATSECT");
  declare_integer("SECTOR_NUMBER_ENDOFCHAIN");
  declare_integer("SECTOR_NUMBER_FREESECT");

  declare_integer("HEADER_SIGNATURE");

  declare_integer("VERSION_MINOR");
  declare_integer("VERSION_MAJOR_3");
  declare_integer("VERSION_MAJOR_4");

  declare_integer("BYTE_ORDER_LITTLE_ENDIAN");

  declare_integer("SECTOR_SHIFT_VERSION_3");
  declare_integer("SECTOR_SHIFT_VERSION_4");
  declare_integer("SECTOR_SIZE_VERSION_3");
  declare_integer("SECTOR_SIZE_VERSION_4");

  declare_integer("MINI_SECTOR_SHIFT");
  declare_integer("MINI_SECTOR_SIZE");

  declare_integer("NUMBER_OF_DIRECTORY_SECTORS_VERSION_3");

  declare_integer("MINI_STREAM_CUTOFF_SIZE");

  declare_integer("STREAM_NUMBER_MAXREGSID");
  declare_integer("STREAM_NUMBER_NOSTREAM");

  declare_integer("OBJECT_TYPE_UNKNOWN");
  declare_integer("OBJECT_TYPE_UNALLOCATED");
  declare_integer("OBJECT_TYPE_STORAGE");
  declare_integer("OBJECT_TYPE_STREAM");
  declare_integer("OBJECT_TYPE_ROOT_STORAGE");

  declare_integer("COLOR_FLAG_RED");
  declare_integer("COLOR_FLAG_BLACK");

  declare_integer("MAX_STREAM_SIZE_VERSION_3");

  // Header
  declare_integer("signature");  // uint64_t to int64_t
  begin_struct("clsid")
    ;
    declare_integer("data1");
    declare_integer("data2");
    declare_integer("data3");
    declare_integer_array("data4");
  end_struct("clsid");
  declare_integer("version_minor");
  declare_integer("version_major");
  declare_integer("byte_order");
  declare_integer("sector_shift");
  declare_integer("mini_sector_shift");
  declare_integer_array("reserved");
  declare_integer("number_of_directory_sectors");
  declare_integer("number_of_fat_sectors");
  declare_integer("first_directory_sector_location");
  declare_integer("transaction_signature");
  declare_integer("mini_stream_cutoff_size");
  declare_integer("first_mini_fat_sector_location");
  declare_integer("number_of_mini_fat_sectors");
  declare_integer("first_difat_sector_location");
  declare_integer("number_of_difat_sectors");

  declare_integer_array("difat_sector_locations");
  declare_integer_array("difat");
  declare_integer_array("fat");
  declare_integer_array("mini_fat_sector_locations");
  declare_integer_array("mini_fat");

  declare_integer("number_of_directories");
  begin_struct_array("directories")
    ;
    declare_string("name");
    declare_integer("name_length");
    declare_integer("object_type");
    declare_integer("color_flag");
    declare_integer("left_sibling_id");
    declare_integer("right_sibling_id");
    declare_integer("child_id");
    begin_struct("clsid")
      ;
      declare_integer("data1");
      declare_integer("data2");
      declare_integer("data3");
      declare_integer_array("data4");
    end_struct("clsid");
    declare_integer("state_bits");
    begin_struct("creation_time")
      ;
      declare_integer("low");
      declare_integer("high");
    end_struct("creation_time");
    begin_struct("modified_time")
      ;
      declare_integer("low");
      declare_integer("high");
    end_struct("modified_time");
    declare_integer("starting_sector_location");
    declare_integer("stream_size");  // uint64_t to int64_t
  end_struct("directories");

  declare_function("uint8_at", "ii", "i", uint8_at_directory_offset);
  declare_function("int8_at", "ii", "i", int8_at_directory_offset);
  declare_function("uint16_at", "ii", "i", uint16_at_directory_offset_le);
  declare_function("uint16be_at", "ii", "i", uint16_at_directory_offset_be);
  declare_function("int16_at", "ii", "i", int16_at_directory_offset_le);
  declare_function("int16be_at", "ii", "i", int16_at_directory_offset_be);
  declare_function("uint32_at", "ii", "i", uint32_at_directory_offset_le);
  declare_function("uint32be_at", "ii", "i", uint32_at_directory_offset_be);
  declare_function("int32_at", "ii", "i", int32_at_directory_offset_le);
  declare_function("int32be_at", "ii", "i", int32_at_directory_offset_be);
  declare_function("uint64_at", "ii", "i", uint64_at_directory_offset_le);
  declare_function("uint64be_at", "ii", "i", uint64_at_directory_offset_be);
  declare_function("int64_at", "ii", "i", int64_at_directory_offset_le);
  declare_function("int64be_at", "ii", "i", int64_at_directory_offset_be);

end_declarations

int module_initialize(YR_MODULE *module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE *module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT *context,
    YR_OBJECT *module_object,
    void *module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK *block;
  YR_MEMORY_BLOCK_ITERATOR *iterator = context->iterator;

  PCOMPOUND_FILE_BINARY_HEADER pHeader;

  cfb_expose_constants(module_object);

  foreach_memory_block(iterator, block)
  {
    // Make sure the header is at least large enough
    pHeader = (PCOMPOUND_FILE_BINARY_HEADER) block->fetch_data(block);

    if (pHeader == NULL || block->size < sizeof(COMPOUND_FILE_BINARY_HEADER))
      continue;

    // Allocate a compound file
    PCOMPOUND_FILE_BINARY pBinary = yr_calloc(1, sizeof(COMPOUND_FILE_BINARY));
    module_object->data = pBinary;
    pBinary->pHeader = pHeader;
    pBinary->dwSize = block->size;
    pBinary->pFat = NULL;
    pBinary->pDifat = NULL;
    pBinary->pMiniFat = NULL;
    pBinary->pMiniFatLocations = NULL;
    pBinary->pDifatLocations = NULL;
    // Only parse the compound file if the header is valid
    if (is_valid_header(pHeader))
    {
      cfb_parse_difat(pBinary);
      cfb_expose_difat(module_object, pBinary);
      cfb_parse_fat(pBinary);
      cfb_expose_fat(module_object, pBinary);
      cfb_parse_directories(pBinary);
      cfb_expose_directories(
          module_object,
          pBinary->pDirectories,
          pBinary->dwNumberOfDirectoryEntries);
      cfb_parse_mini_fat(pBinary);
      cfb_expose_mini_fat(module_object, pBinary);
    }

    // Expose the header as it was valid
    cfb_expose_header(module_object, pBinary->pHeader);
    break;
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT *module_object)
{
  PCOMPOUND_FILE_BINARY pBinary = module_object->data;
  if (pBinary)
  {
    if (pBinary->pDifat)
      yr_free(pBinary->pDifat);
    if (pBinary->pDifatLocations)
      yr_free(pBinary->pDifatLocations);
    if (pBinary->pFat)
      yr_free(pBinary->pFat);
    if (pBinary->pDirectories)
      yr_free(pBinary->pDirectories);
    if (pBinary->pMiniFatLocations)
      yr_free(pBinary->pMiniFatLocations);
    if (pBinary->pMiniFat)
      yr_free(pBinary->pMiniFat);
    yr_free(pBinary);
  }
  return ERROR_SUCCESS;
}

static bool is_valid_header(PCOMPOUND_FILE_BINARY_HEADER pHeader)
{
  return
      // Identification signature for the compound file structure, and MUST be
      // set to the HEADER_SIGNATURE value.
      yr_le64toh(pHeader->signature) == HEADER_SIGNATURE &&

      // Reserved and unused class ID that MUST be set to all zeroes
      // (CLSID_NULL).
      IsEqualGUID(pHeader->clsid, CLSID_NULL) &&

      // Version number for nonbreaking changes SHOULD be set to VERSION_MINOR
      // if the major version field is either VERSION_MAJOR_3 or
      // VERSION_MAJOR_4. Version number for breaking changes MUST be set to
      // either VERSION_MAJOR_3 or VERSION_MAJOR_4.
      yr_le16toh(pHeader->version_minor) == VERSION_MINOR &&
      (yr_le16toh(pHeader->version_major) == VERSION_MAJOR_3 ||
       yr_le16toh(pHeader->version_major) == VERSION_MAJOR_4) &&

      // This field MUST be set to BYTE_ORDER_LITTLE_ENDIAN
      yr_le16toh(pHeader->byte_order) == BYTE_ORDER_LITTLE_ENDIAN &&

      // This field MUST be set to SECTOR_SHIFT_VERSION_3, or
      // SECTOR_SHIFT_VERSION_4, depending on the Major Version field.
      ((yr_le16toh(pHeader->version_major) == VERSION_MAJOR_3 &&
        yr_le16toh(pHeader->sector_shift) == SECTOR_SHIFT_VERSION_3) ||
       (yr_le16toh(pHeader->version_major) == VERSION_MAJOR_4 &&
        yr_le16toh(pHeader->sector_shift) == SECTOR_SHIFT_VERSION_4)) &&

      // This field MUST be set to MINI_SECTOR_SHIFT.
      yr_le16toh(pHeader->mini_sector_shift) == MINI_SECTOR_SHIFT &&

      // This field MUST be set to all zeroes.
      !pHeader->reserved[0] && !pHeader->reserved[1] && !pHeader->reserved[2] &&
      !pHeader->reserved[3] && !pHeader->reserved[4] && !pHeader->reserved[5] &&

      // If Major Version is 3, the Number of Directory Sectors MUST be zero.
      (yr_le16toh(pHeader->version_major) != VERSION_MAJOR_3 ||
       yr_le32toh(pHeader->number_of_directory_sectors) == 0) &&

      // This integer field MUST be set to MINI_STREAM_CUTOFF_SIZE.
      yr_le32toh(pHeader->mini_stream_cutoff_size) == MINI_STREAM_CUTOFF_SIZE;
}

static void cfb_parse_difat(PCOMPOUND_FILE_BINARY pBinary)
{
  // Compute the header difat and sector difat length
  DWORD dwHeaderDifatLength = sizeof(pBinary->pHeader->difat) / sizeof(DWORD);
  DWORD dwSectorSize = 1 << yr_le16toh(pBinary->pHeader->sector_shift);
  DWORD dwDifatSectorLength = (dwSectorSize / sizeof(DWORD)) - 1;

  // Allocate the required arrays, including for the ENDOFCHAIN
  DWORD dwNumberOfDifatSectors = yr_le32toh(
      pBinary->pHeader->number_of_difat_sectors);
  DWORD dwNumberOfDifatLocations = dwNumberOfDifatSectors + 1;
  pBinary->pDifatLocations = yr_calloc(dwNumberOfDifatLocations, sizeof(DWORD));

  DWORD dwNumberOfDifatEntries = dwHeaderDifatLength +
                                 dwNumberOfDifatSectors * dwDifatSectorLength;
  pBinary->pDifat = yr_calloc(dwNumberOfDifatEntries, sizeof(DWORD));

  // Walk the header difat
  for (int i = 0; i < dwHeaderDifatLength; i++)
  {
    DWORD dwFatLocation = yr_le32toh(pBinary->pHeader->difat[i]);
    pBinary->pDifat[i] = dwFatLocation;
  }

  // Only loop number_of_difat_sectors sectors to avoid infinite loops and
  // ensure the next difat sector is within bounds
  DWORD dwDifatLocation = yr_le32toh(
      pBinary->pHeader->first_difat_sector_location);

  for (int i = 0; i < dwNumberOfDifatSectors &&
                  dwDifatLocation != SECTOR_NUMBER_ENDOFCHAIN &&
                  dwSectorSize * (dwDifatLocation + 2) <= pBinary->dwSize;
       i++)
  {
    // Update the difat locations
    pBinary->dwNumberOfDifatLocations = i + 1;
    pBinary->pDifatLocations[i] = dwDifatLocation;

    // Walk the difat sector
    DWORD *pDifat =
        (DWORD
             *) (((BYTE *) pBinary->pHeader) + dwSectorSize * (dwDifatLocation + 1));

    for (int j = 0; j < dwDifatSectorLength; j++)
    {
      DWORD dwFatLocation = yr_le32toh(pDifat[j]);
      pBinary->pDifat[dwHeaderDifatLength + (dwDifatSectorLength * i) + j] =
          dwFatLocation;
    }

    // Define next difat in chain
    dwDifatLocation = yr_le32toh(pDifat[dwDifatSectorLength]);
  }

  // Update the number of set difat entries
  pBinary->dwNumberOfDifatEntries = dwHeaderDifatLength +
                                    pBinary->dwNumberOfDifatLocations *
                                        dwDifatSectorLength;

  // Store the last difat location, which is expected to be an ENDOFCHAIN
  pBinary->pDifatLocations[pBinary->dwNumberOfDifatLocations] = dwDifatLocation;
  pBinary->dwNumberOfDifatLocations++;
}

static void cfb_parse_fat(PCOMPOUND_FILE_BINARY pBinary)
{
  // Compute the fat sector length
  DWORD dwSectorSize = 1 << yr_le16toh(pBinary->pHeader->sector_shift);
  DWORD dwFatSectorLength = dwSectorSize / sizeof(DWORD);

  // Allocate the required arrays
  pBinary->dwNumberOfFatEntries = 0;
  for (int i = 0; i < pBinary->dwNumberOfDifatEntries &&
                  pBinary->pDifat[i] <= SECTOR_NUMBER_MAXREGSECT;
       i++)
    pBinary->dwNumberOfFatEntries += dwFatSectorLength;
  pBinary->pFat = yr_calloc(pBinary->dwNumberOfFatEntries, sizeof(DWORD));

  // Walk difat
  for (int i = 0; i < pBinary->dwNumberOfDifatEntries &&
                  pBinary->pDifat[i] <= SECTOR_NUMBER_MAXREGSECT &&
                  dwSectorSize * (pBinary->pDifat[i] + 2) <= pBinary->dwSize;
       i++)
  {
    // Walk fat
    DWORD dwFatLocation = pBinary->pDifat[i];
    DWORD *pFat =
        (DWORD
             *) (((BYTE *) pBinary->pHeader) + dwSectorSize * (dwFatLocation + 1));

    for (int j = 0; j < dwFatSectorLength; j++)
    {
      DWORD dwFatEntry = pFat[j];
      pBinary->pFat[dwFatSectorLength * i + j] = dwFatEntry;
    }
  }
}

static void cfb_parse_mini_fat(PCOMPOUND_FILE_BINARY pBinary)
{
  // Compute the mini fat sector length
  DWORD dwSectorSize = 1 << yr_le16toh(pBinary->pHeader->sector_shift);
  DWORD dwMiniFatLength = dwSectorSize / sizeof(DWORD);
  DWORD dwNumberOfMiniFatSectors = yr_le32toh(
      pBinary->pHeader->number_of_mini_fat_sectors);

  // Allocate the required arrays, including for the ENDOFCHAIN
  DWORD dwNumberOfMiniFatLocations = dwNumberOfMiniFatSectors + 1;
  pBinary->pMiniFatLocations = yr_calloc(
      dwNumberOfMiniFatLocations, sizeof(DWORD));

  pBinary->dwNumberOfMiniFatEntries = dwNumberOfMiniFatSectors *
                                      dwMiniFatLength;
  pBinary->pMiniFat = yr_calloc(
      pBinary->dwNumberOfMiniFatEntries, sizeof(DWORD));

  // Walk mini fat
  DWORD dwMiniFatLocation = yr_le32toh(
      pBinary->pHeader->first_mini_fat_sector_location);
  for (int i = 0; i < dwNumberOfMiniFatSectors &&
                  dwMiniFatLocation <= SECTOR_NUMBER_MAXREGSECT &&
                  dwSectorSize * (dwMiniFatLocation + 2) <= pBinary->dwSize;
       i++)
  {
    // Update the mini fat locations
    pBinary->dwNumberOfMiniFatLocations = i + 1;
    pBinary->pMiniFatLocations[i] = dwMiniFatLocation;

    // Walk the mini fat entries
    DWORD *pMiniFat =
        (DWORD
             *) (((BYTE *) pBinary->pHeader) + dwSectorSize * (dwMiniFatLocation + 1));

    for (int j = 0; j < dwMiniFatLength; j++)
    {
      DWORD dwMiniFatEntry = pMiniFat[j];
      pBinary->pMiniFat[dwMiniFatLength * i + j] = dwMiniFatEntry;
    }

    // Define the next mini fat location
    dwMiniFatLocation = pBinary->pFat[dwMiniFatLocation];
  }

  // Update the number of set mini fat entries
  pBinary->dwNumberOfMiniFatEntries = pBinary->dwNumberOfMiniFatLocations *
                                      dwMiniFatLength;

  // Store the last mini fat location, which is expected to be an ENDOFCHAIN
  pBinary->pMiniFatLocations[pBinary->dwNumberOfMiniFatLocations] =
      dwMiniFatLocation;
  pBinary->dwNumberOfMiniFatLocations++;
}

static void cfb_parse_directories(PCOMPOUND_FILE_BINARY pBinary)
{
  DWORD dwSectorSize = 1 << yr_le16toh(pBinary->pHeader->sector_shift);
  DWORD dwDirectorySectorLength = dwSectorSize / sizeof(DIRECTORY_ENTRY);

  // Number of Directory Sectors; If Major Version is 3, the Number of Directory
  // Sectors MUST be zero. This field is not supported for version 3 compound
  // files.
  bool bIsVersion3 = yr_le32toh(pBinary->pHeader->version_major) ==
                     VERSION_MAJOR_3;
  DWORD dwNumberOfDirectorySectors =
      bIsVersion3 ? 0
                  : yr_le32toh(pBinary->pHeader->number_of_directory_sectors);
  if (bIsVersion3)
  {
    for (DWORD dwDirectorySectorLocation =
             yr_le32toh(pBinary->pHeader->first_directory_sector_location);
         dwNumberOfDirectorySectors <= SECTOR_NUMBER_MAXREGSECT &&
         dwDirectorySectorLocation <= SECTOR_NUMBER_MAXREGSECT &&
         dwDirectorySectorLocation < pBinary->dwNumberOfFatEntries;
         dwDirectorySectorLocation = pBinary->pFat[dwDirectorySectorLocation])
    {
      dwNumberOfDirectorySectors++;
    }
  }

  pBinary->dwNumberOfDirectoryEntries = dwNumberOfDirectorySectors *
                                        dwDirectorySectorLength;
  pBinary->pDirectories = yr_calloc(
      pBinary->dwNumberOfDirectoryEntries, sizeof(PDIRECTORY_ENTRY));

  // Walk directory sectors
  DWORD dwDirectorySectorLocation = yr_le32toh(
      pBinary->pHeader->first_directory_sector_location);
  for (int i = 0;
       i < dwNumberOfDirectorySectors &&
       dwDirectorySectorLocation <= SECTOR_NUMBER_MAXREGSECT &&
       dwSectorSize * (dwDirectorySectorLocation + 2) <= pBinary->dwSize;
       i++)
  {
    PDIRECTORY_ENTRY pDirectoryEntries =
        (PDIRECTORY_ENTRY) (((BYTE *) pBinary->pHeader) + dwSectorSize * (dwDirectorySectorLocation + 1));

    // Walk the directory entries
    for (int j = 0; j < dwDirectorySectorLength; j++)
    {
      PDIRECTORY_ENTRY pDirectoryEntry = &pDirectoryEntries[j];
      pBinary->pDirectories[i * dwDirectorySectorLength + j] = pDirectoryEntry;
    }

    dwDirectorySectorLocation = pBinary->pFat[dwDirectorySectorLocation];
  }
}

static void cfb_expose_constants(YR_OBJECT *module_object)
{
  yr_set_integer(0, module_object, "is_cfb");

  yr_set_integer(
      SECTOR_NUMBER_MAXREGSECT, module_object, "SECTOR_NUMBER_MAXREGSECT");
  yr_set_integer(SECTOR_NUMBER_DIFSECT, module_object, "SECTOR_NUMBER_DIFSECT");
  yr_set_integer(SECTOR_NUMBER_FATSECT, module_object, "SECTOR_NUMBER_FATSECT");
  yr_set_integer(
      SECTOR_NUMBER_ENDOFCHAIN, module_object, "SECTOR_NUMBER_ENDOFCHAIN");
  yr_set_integer(
      SECTOR_NUMBER_FREESECT, module_object, "SECTOR_NUMBER_FREESECT");
  yr_set_integer(HEADER_SIGNATURE, module_object, "HEADER_SIGNATURE");
  yr_set_integer(VERSION_MINOR, module_object, "VERSION_MINOR");
  yr_set_integer(VERSION_MAJOR_3, module_object, "VERSION_MAJOR_3");
  yr_set_integer(VERSION_MAJOR_4, module_object, "VERSION_MAJOR_4");
  yr_set_integer(
      BYTE_ORDER_LITTLE_ENDIAN, module_object, "BYTE_ORDER_LITTLE_ENDIAN");
  yr_set_integer(
      SECTOR_SHIFT_VERSION_3, module_object, "SECTOR_SHIFT_VERSION_3");
  yr_set_integer(
      SECTOR_SHIFT_VERSION_4, module_object, "SECTOR_SHIFT_VERSION_4");
  yr_set_integer(SECTOR_SIZE_VERSION_3, module_object, "SECTOR_SIZE_VERSION_3");
  yr_set_integer(SECTOR_SIZE_VERSION_4, module_object, "SECTOR_SIZE_VERSION_4");
  yr_set_integer(MINI_SECTOR_SHIFT, module_object, "MINI_SECTOR_SHIFT");
  yr_set_integer(MINI_SECTOR_SIZE, module_object, "MINI_SECTOR_SIZE");
  yr_set_integer(
      NUMBER_OF_DIRECTORY_SECTORS_VERSION_3,
      module_object,
      "NUMBER_OF_DIRECTORY_SECTORS_VERSION_3");
  yr_set_integer(
      MINI_STREAM_CUTOFF_SIZE, module_object, "MINI_STREAM_CUTOFF_SIZE");
  yr_set_integer(
      MINI_STREAM_CUTOFF_SIZE, module_object, "MINI_STREAM_CUTOFF_SIZE");
  yr_set_integer(
      STREAM_NUMBER_MAXREGSID, module_object, "STREAM_NUMBER_MAXREGSID");
  yr_set_integer(
      STREAM_NUMBER_NOSTREAM, module_object, "STREAM_NUMBER_NOSTREAM");
  yr_set_integer(OBJECT_TYPE_UNKNOWN, module_object, "OBJECT_TYPE_UNKNOWN");
  yr_set_integer(
      OBJECT_TYPE_UNALLOCATED, module_object, "OBJECT_TYPE_UNALLOCATED");
  yr_set_integer(OBJECT_TYPE_STORAGE, module_object, "OBJECT_TYPE_STORAGE");
  yr_set_integer(OBJECT_TYPE_STREAM, module_object, "OBJECT_TYPE_STREAM");
  yr_set_integer(
      OBJECT_TYPE_ROOT_STORAGE, module_object, "OBJECT_TYPE_ROOT_STORAGE");
  yr_set_integer(COLOR_FLAG_RED, module_object, "COLOR_FLAG_RED");
  yr_set_integer(COLOR_FLAG_BLACK, module_object, "COLOR_FLAG_BLACK");
  yr_set_integer(
      MAX_STREAM_SIZE_VERSION_3, module_object, "MAX_STREAM_SIZE_VERSION_3");
}

static void cfb_expose_header(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY_HEADER pHeader)
{
  yr_set_integer(is_valid_header(pHeader), module_object, "is_cfb");

  yr_set_integer(yr_le64toh(pHeader->signature), module_object, "signature");
  yr_set_integer(
      yr_le32toh(pHeader->clsid.Data1), module_object, "clsid.data1");
  yr_set_integer(
      yr_le16toh(pHeader->clsid.Data2), module_object, "clsid.data2");
  yr_set_integer(
      yr_le16toh(pHeader->clsid.Data3), module_object, "clsid.data3");
  for (int i = 0; i < sizeof(pHeader->clsid.Data4) / sizeof(BYTE); i++)
  {
    yr_set_integer(
        pHeader->clsid.Data4[i], module_object, "clsid.data4[%i]", i);
  }
  yr_set_integer(
      yr_le16toh(pHeader->version_minor), module_object, "version_minor");
  yr_set_integer(
      yr_le16toh(pHeader->version_major), module_object, "version_major");
  yr_set_integer(yr_le16toh(pHeader->byte_order), module_object, "byte_order");
  yr_set_integer(
      yr_le16toh(pHeader->sector_shift), module_object, "sector_shift");
  yr_set_integer(
      yr_le16toh(pHeader->mini_sector_shift),
      module_object,
      "mini_sector_shift");
  for (int i = 0; i < sizeof(pHeader->reserved) / sizeof(BYTE); i++)
  {
    yr_set_integer(pHeader->reserved[i], module_object, "reserved[%i]", i);
  }
  yr_set_integer(
      yr_le32toh(pHeader->number_of_directory_sectors),
      module_object,
      "number_of_directory_sectors");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_fat_sectors),
      module_object,
      "number_of_fat_sectors");
  yr_set_integer(
      yr_le32toh(pHeader->first_directory_sector_location),
      module_object,
      "first_directory_sector_location");
  yr_set_integer(
      yr_le32toh(pHeader->transaction_signature),
      module_object,
      "transaction_signature");
  yr_set_integer(
      yr_le32toh(pHeader->mini_stream_cutoff_size),
      module_object,
      "mini_stream_cutoff_size");
  yr_set_integer(
      yr_le32toh(pHeader->first_mini_fat_sector_location),
      module_object,
      "first_mini_fat_sector_location");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_mini_fat_sectors),
      module_object,
      "number_of_mini_fat_sectors");
  yr_set_integer(
      yr_le32toh(pHeader->first_difat_sector_location),
      module_object,
      "first_difat_sector_location");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_difat_sectors),
      module_object,
      "number_of_difat_sectors");
}

static void cfb_expose_difat(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY pBinary)
{
  for (int i = 0; i < pBinary->dwNumberOfDifatLocations; i++)
  {
    yr_set_integer(
        pBinary->pDifatLocations[i],
        module_object,
        "difat_sector_locations[%i]",
        i);
  }
  for (int i = 0; i < pBinary->dwNumberOfDifatEntries; i++)
  {
    yr_set_integer(pBinary->pDifat[i], module_object, "difat[%i]", i);
  }
}

static void cfb_expose_fat(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY pBinary)
{
  for (int i = 0; i < pBinary->dwNumberOfFatEntries; i++)
  {
    yr_set_integer(pBinary->pFat[i], module_object, "fat[%i]", i);
  }
}

static void cfb_expose_mini_fat(
    YR_OBJECT *module_object,
    PCOMPOUND_FILE_BINARY pBinary)
{
  for (int i = 0; i < pBinary->dwNumberOfMiniFatLocations; i++)
  {
    yr_set_integer(
        pBinary->pMiniFatLocations[i],
        module_object,
        "mini_fat_sector_locations[%i]",
        i);
  }
  for (int i = 0; i < pBinary->dwNumberOfMiniFatEntries; i++)
  {
    yr_set_integer(pBinary->pMiniFat[i], module_object, "mini_fat[%i]", i);
  }
}

static void cfb_expose_directories(
    YR_OBJECT *module_object,
    PDIRECTORY_ENTRY *pDirectories,
    DWORD dwNumberOfDirectoryEntries)
{
  for (int i = 0; i < dwNumberOfDirectoryEntries; i++)
  {
    yr_set_integer(
        pDirectories[i]->object_type,
        module_object,
        "directories[%i].object_type",
        i);
    // Do not set the name if the directory is unallocated or if the name length
    // does not make sense
    if (pDirectories[i]->object_type != OBJECT_TYPE_UNALLOCATED &&
        yr_le16toh(pDirectories[i]->name_length) >= 2 &&
        yr_le16toh(pDirectories[i]->name_length) <= 64)
      yr_set_sized_string(
          (const char *) pDirectories[i]->name,
          yr_le16toh(pDirectories[i]->name_length) - 2,
          module_object,
          "directories[%i].name",
          i);
    yr_set_integer(
        yr_le16toh(pDirectories[i]->name_length),
        module_object,
        "directories[%i].name_length",
        i);
    yr_set_integer(
        pDirectories[i]->color_flag,
        module_object,
        "directories[%i].color_flag",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->left_sibling_id),
        module_object,
        "directories[%i].left_sibling_id",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->right_sibling_id),
        module_object,
        "directories[%i].right_sibling_id",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->child_id),
        module_object,
        "directories[%i].child_id",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->clsid.Data1),
        module_object,
        "directories[%i].clsid.data1",
        i);
    yr_set_integer(
        yr_le16toh(pDirectories[i]->clsid.Data2),
        module_object,
        "directories[%i].clsid.data2",
        i);
    yr_set_integer(
        yr_le16toh(pDirectories[i]->clsid.Data3),
        module_object,
        "directories[%i].clsid.data3",
        i);
    for (int j = 0; j < sizeof(pDirectories[i]->clsid.Data4) / sizeof(BYTE);
         j++)
    {
      yr_set_integer(
          pDirectories[i]->clsid.Data4[j],
          module_object,
          "directories[%i].clsid.data4[%i]",
          i,
          j);
    }
    yr_set_integer(
        yr_le32toh(pDirectories[i]->state_bits),
        module_object,
        "directories[%i].state_bits",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->creation_time.dwLowDateTime),
        module_object,
        "directories[%i].creation_time.low",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->creation_time.dwHighDateTime),
        module_object,
        "directories[%i].creation_time.high",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->modified_time.dwLowDateTime),
        module_object,
        "directories[%i].modified_time.low",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->modified_time.dwHighDateTime),
        module_object,
        "directories[%i].modified_time.high",
        i);
    yr_set_integer(
        yr_le32toh(pDirectories[i]->starting_sector_location),
        module_object,
        "directories[%i].starting_sector_location",
        i);
    yr_set_integer(
        yr_le64toh(pDirectories[i]->stream_size),
        module_object,
        "directories[%i].stream_size",
        i);
  }

  yr_set_integer(
      yr_le64toh(dwNumberOfDirectoryEntries),
      module_object,
      "number_of_directories");
}

static bool cfb_uint8_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint8_t *bOut)
{
  // Require some valid CFB
  if (pBinary == NULL || pBinary->pHeader == NULL ||
      !is_valid_header(pBinary->pHeader) || pBinary->pDirectories == NULL ||
      dwDirectory >= pBinary->dwNumberOfDirectoryEntries ||
      pBinary->pDirectories[dwDirectory]->object_type != OBJECT_TYPE_STREAM ||
      qwOffset >= pBinary->pDirectories[dwDirectory]->stream_size)
    return false;

  // Identify the sector's table
  DWORD *pTable = pBinary->pDirectories[dwDirectory]->stream_size >=
                          MINI_STREAM_CUTOFF_SIZE
                      ? pBinary->pFat
                      : pBinary->pMiniFat;
  DWORD dwTableSize = pBinary->pDirectories[dwDirectory]->stream_size >=
                              MINI_STREAM_CUTOFF_SIZE
                          ? pBinary->dwNumberOfFatEntries
                          : pBinary->dwNumberOfMiniFatEntries;

  // Identify the sector's size
  DWORD dwSize = pBinary->pDirectories[dwDirectory]->stream_size >=
                         MINI_STREAM_CUTOFF_SIZE
                     ? (1 << pBinary->pHeader->sector_shift)
                     : MINI_SECTOR_SIZE;

  // Walk the table to find the correct sector
  DWORD dwLocation =
      pBinary->pDirectories[dwDirectory]->starting_sector_location;
  while (qwOffset >= dwSize)
  {
    if (dwLocation >= dwTableSize)
      return false;
    dwLocation = pTable[dwLocation];
    qwOffset -= dwSize;
  }

  // Convert the Mini FAT location/offset to FAT location/offset
  if (pBinary->pDirectories[dwDirectory]->stream_size < MINI_STREAM_CUTOFF_SIZE)
  {
    qwOffset += dwLocation * MINI_SECTOR_SIZE;
    dwLocation = pBinary->pDirectories[0]->starting_sector_location;
    dwSize = (1 << pBinary->pHeader->sector_shift);
    while (qwOffset >= dwSize)
    {
      if (dwLocation >= pBinary->dwNumberOfFatEntries)
        return NULL;
      dwLocation = pBinary->pFat[dwLocation];
      qwOffset -= dwSize;
    }
  }

  // Convert the location to a file offset
  *bOut = *(((BYTE *) pBinary->pHeader) + dwSize * (dwLocation + 1) + qwOffset);
  return true;
}

static bool cfb_uint16_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint16_t *uOut)
{
  uint8_t n;
  for (int i = 0; i < sizeof(*uOut); i++)
  {
    if (!cfb_uint8_at_directory_offset(pBinary, dwDirectory, qwOffset + i, &n))
      return false;
    *uOut <<= 8;
    *uOut += n;
  }
  return true;
}

static bool cfb_uint32_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint32_t *uOut)
{
  uint8_t n;
  for (int i = 0; i < sizeof(*uOut); i++)
  {
    if (!cfb_uint8_at_directory_offset(pBinary, dwDirectory, qwOffset + i, &n))
      return false;
    *uOut <<= 8;
    *uOut += n;
  }
  return true;
}

static bool cfb_uint64_at_directory_offset(
    PCOMPOUND_FILE_BINARY pBinary,
    DWORD dwDirectory,
    ULONGLONG qwOffset,
    uint64_t *uOut)
{
  uint8_t n;
  for (int i = 0; i < sizeof(*uOut); i++)
  {
    if (!cfb_uint8_at_directory_offset(pBinary, dwDirectory, qwOffset + i, &n))
      return false;
    *uOut <<= 8;
    *uOut += n;
  }
  return true;
}
