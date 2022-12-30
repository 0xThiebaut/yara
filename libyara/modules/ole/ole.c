#pragma clang diagnostic push
#pragma ide diagnostic ignored "EmptyDeclOrStmt"
#include <yara/endian.h>
#include <yara/modules.h>

#define MODULE_NAME ole

/**
 * Windows types and macros
 */

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

// https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
typedef struct _FILETIME
{
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

// https://learn.microsoft.com/en-us/windows/win32/api/guiddef/nf-guiddef-isequalguid
#define IsEqualGUID(rguid1, rguid2)                                        \
  ((rguid1).Data1 == (rguid2).Data1 && (rguid1).Data2 == (rguid2).Data2 && \
   (rguid1).Data3 == (rguid2).Data3 && (rguid1).Data4 == (rguid2).Data4)

/**
 * Compound File Binary File Format types and macros
 */

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/9d33df18-7aee-4065-9121-4eabe41c29d4
#define SECTOR_NUMBER_MAXREGSECT 0xFFFFFFFA
#define SECTOR_NUMBER_DIFSECT    0xFFFFFFFC
#define SECTOR_NUMBER_FATSECT    0xFFFFFFFD
#define SECTOR_NUMBER_ENDOFCHAIN 0xFFFFFFFE
#define SECTOR_NUMBER_FREESECT   0xFFFFFFFF

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
typedef struct _COMPOUND_FILE_HEADER
{
  ULONGLONG signature;
  GUID clsid;
  WORD version_minor;
  WORD version_major;
  WORD byte_order;
  WORD sector_shift;
  WORD mini_sector_shift;
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
  ULONG difat[109];
} COMPOUND_FILE_HEADER, *PCOMPOUND_FILE_HEADER;

#define HEADER_SIGNATURE \
  0xE11AB1A1E011CFD0  // 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1

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
#define MINI_SECTOR_SIZE  1 << MINI_SECTOR_SHIFT

#define NUMBER_OF_DIRECTORY_SECTORS_VERSION_3 0x00000000

#define MINI_STREAM_CUTOFF_SIZE 0x00001000

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

#define STREAM_NUMBER_MAXREGSID 0xFFFFFFFA
#define STREAM_NUMBER_NOSTREAM  0xFFFFFFFF

typedef struct _DIRECTORY_ENTRY
{
  WCHAR name[32];
  WORD name_length;
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

#define MAX_STREAM_SIZE_VERSION_3 0x80000000

/**
 * Declarations
 */

begin_declarations
  declare_integer("is_ole");

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
  begin_struct("header")
    ;
    // Don't expose the signature as uint64_t is not properly supported Yara
    // declare_integer("signature");
    begin_struct("clsid")
      ;
      declare_integer("data1");
      declare_integer("data2");
      declare_integer("data3");
      declare_integer("data4");
    end_struct("clsid");
    declare_integer("version_minor");
    declare_integer("version_major");
    declare_integer("byte_order");
    declare_integer("sector_shift");
    declare_integer("mini_sector_shift");
    declare_integer("reserved");
    declare_integer("number_of_directory_sectors");
    declare_integer("number_of_fat_sectors");
    declare_integer("first_directory_sector_location");
    declare_integer("transaction_signature");
    declare_integer("mini_stream_cutoff_size");
    declare_integer("first_mini_fat_sector_location");
    declare_integer("number_of_mini_fat_sectors");
    declare_integer("first_difat_sector_location");
    declare_integer("number_of_difat_sectors");
    // @TODO: Difat appart?
  end_struct("header");

end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

void set_constants(YR_OBJECT* module_object)
{
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

void set_file_header(YR_OBJECT* module_object, PCOMPOUND_FILE_HEADER pHeader)
{
  // Don't expose the signature as uint64_t is not properly supported Yara
  // yr_set_integer(pHeader->signature, module_object, "header.signature");
  yr_set_integer(
      yr_le32toh(pHeader->clsid.Data1), module_object, "header.clsid.data1");
  yr_set_integer(
      yr_le16toh(pHeader->clsid.Data2), module_object, "header.clsid.data2");
  yr_set_integer(
      yr_le16toh(pHeader->clsid.Data3), module_object, "header.clsid.data3");
  yr_set_integer(
      yr_le64toh(pHeader->clsid.Data4), module_object, "header.clsid.data4");
  yr_set_integer(
      yr_le16toh(pHeader->version_minor),
      module_object,
      "header.version_minor");
  yr_set_integer(
      yr_le16toh(pHeader->version_major),
      module_object,
      "header.version_major");
  yr_set_integer(
      yr_le16toh(pHeader->byte_order), module_object, "header.byte_order");
  yr_set_integer(
      yr_le16toh(pHeader->sector_shift), module_object, "header.sector_shift");
  yr_set_integer(
      yr_le16toh(pHeader->mini_sector_shift),
      module_object,
      "header.mini_sector_shift");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_directory_sectors),
      module_object,
      "header.number_of_directory_sectors");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_fat_sectors),
      module_object,
      "header.number_of_fat_sectors");
  yr_set_integer(
      yr_le32toh(pHeader->first_directory_sector_location),
      module_object,
      "header.first_directory_sector_location");
  yr_set_integer(
      yr_le32toh(pHeader->transaction_signature),
      module_object,
      "header.transaction_signature");
  yr_set_integer(
      yr_le32toh(pHeader->mini_stream_cutoff_size),
      module_object,
      "header.mini_stream_cutoff_size");
  yr_set_integer(
      yr_le32toh(pHeader->first_mini_fat_sector_location),
      module_object,
      "header.first_mini_fat_sector_location");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_mini_fat_sectors),
      module_object,
      "header.number_of_mini_fat_sectors");
  yr_set_integer(
      yr_le32toh(pHeader->first_difat_sector_location),
      module_object,
      "header.first_difat_sector_location");
  yr_set_integer(
      yr_le32toh(pHeader->number_of_difat_sectors),
      module_object,
      "header.number_of_difat_sectors");
}

bool is_valid_header(PCOMPOUND_FILE_HEADER pHeader)
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

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  const uint8_t* block_data = NULL;
  COMPOUND_FILE_HEADER* pHeader = NULL;

  yr_set_integer(0, module_object, "is_ole");
  set_constants(module_object);

  foreach_memory_block(iterator, block)
  {
    block_data = block->fetch_data(block);

    // Cast to COMPOUND_FILE_HEADER.
    if (block_data == NULL || block->size < sizeof(COMPOUND_FILE_HEADER))
      continue;

    pHeader = (PCOMPOUND_FILE_HEADER) block_data;
    set_file_header(module_object, pHeader);

    if (!is_valid_header(pHeader))
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

#pragma clang diagnostic pop