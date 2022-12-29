#pragma clang diagnostic push
#pragma ide diagnostic ignored "EmptyDeclOrStmt"
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

  // Constants
  declare_integer("MAXREGSECT");
  declare_integer("DIFSECT");
  declare_integer("FATSECT");
  declare_integer("ENDOFCHAIN");
  declare_integer("FREESECT");

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

  // Header
  begin_struct("compound_file_header")
    ;
    begin_struct("header_clsid")
      ;
      declare_integer("data1");
      declare_integer("data2");
      declare_integer("data3");
      declare_integer("data4");
    end_struct("header_clsid");
    declare_integer("version_minor");
    declare_integer("version_major");
  end_struct("compound_file_header");

end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

void set_constants(YR_OBJECT* module_object){
  yr_set_integer(MAXREGSECT, module_object, "MAXREGSECT");
  yr_set_integer(DIFSECT, module_object, "DIFSECT");
  yr_set_integer(FATSECT, module_object, "FATSECT");
  yr_set_integer(ENDOFCHAIN, module_object, "ENDOFCHAIN");
  yr_set_integer(FREESECT, module_object, "FREESECT");
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
}

void set_file_header(YR_OBJECT* module_object, PCOMPOUND_FILE_HEADER pHeader)
{
  yr_set_integer(
      pHeader->header_clsid.Data1,
      module_object,
      "compound_file_header.header_clsid.data1");
  yr_set_integer(
      pHeader->header_clsid.Data2,
      module_object,
      "compound_file_header.header_clsid.data2");
  yr_set_integer(
      pHeader->header_clsid.Data3,
      module_object,
      "compound_file_header.header_clsid.data3");
  yr_set_integer(
      pHeader->header_clsid.Data4,
      module_object,
      "compound_file_header.header_clsid.data4");
  yr_set_integer(
      pHeader->version_minor,
      module_object,
      "compound_file_header.version_minor");
  yr_set_integer(
      pHeader->version_major,
      module_object,
      "compound_file_header.version_major");
}

bool is_valid_header(PCOMPOUND_FILE_HEADER pHeader)
{
  return
      // Identification signature for the compound file structure, and MUST be
      // set to the HEADER_SIGNATURE value.
      pHeader->header_signature == HEADER_SIGNATURE &&

      // Reserved and unused class ID that MUST be set to all zeroes
      // (CLSID_NULL).
      IsEqualGUID(pHeader->header_clsid, CLSID_NULL) &&

      // Version number for nonbreaking changes SHOULD be set to VERSION_MINOR
      // if the major version field is either VERSION_MAJOR_3 or
      // VERSION_MAJOR_4. Version number for breaking changes MUST be set to
      // either VERSION_MAJOR_3 or VERSION_MAJOR_4.
      pHeader->version_minor == VERSION_MINOR &&
      (pHeader->version_major == VERSION_MAJOR_3 ||
       pHeader->version_major == VERSION_MAJOR_4) &&

      // This field MUST be set to BYTE_ORDER_LITTLE_ENDIAN
      pHeader->byte_order == BYTE_ORDER_LITTLE_ENDIAN &&

      // This field MUST be set to SECTOR_SHIFT_VERSION_3, or
      // SECTOR_SHIFT_VERSION_4, depending on the Major Version field.
      ((pHeader->version_major == VERSION_MAJOR_3 &&
        pHeader->sector_shift == SECTOR_SHIFT_VERSION_3) ||
       (pHeader->version_major == VERSION_MAJOR_4 &&
        pHeader->sector_shift == SECTOR_SHIFT_VERSION_4)) &&

      // This field MUST be set to MINI_SECTOR_SHIFT.
      pHeader->mini_sector_shift == MINI_SECTOR_SHIFT &&

      // This field MUST be set to all zeroes.
      !pHeader->reserved[0] && !pHeader->reserved[1] && !pHeader->reserved[2] &&
      !pHeader->reserved[3] && !pHeader->reserved[4] && !pHeader->reserved[5] &&

      // If Major Version is 3, the Number of Directory Sectors MUST be zero.
      (pHeader->version_major != VERSION_MAJOR_3 ||
       pHeader->number_of_directory_sectors == 0) &&

      // This integer field MUST be set to MINI_STREAM_CUTOFF_SIZE.
      pHeader->mini_stream_cutoff_size == MINI_STREAM_CUTOFF_SIZE;
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