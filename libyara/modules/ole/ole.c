#pragma clang diagnostic push
#pragma ide diagnostic ignored "EmptyDeclOrStmt"
#include <wchar.h>
#include <yara/endian.h>
#include <yara/modules.h>
#include "yara/mem.h"

#define MODULE_NAME ole

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
  ULONGLONG Data4;
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
   (rguid1).Data3 == (rguid2).Data3 && (rguid1).Data4 == (rguid2).Data4)

/**
 * Structures
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/28488197-8193-49d7-84d8-dfd692418ccd
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

#define MAX_STREAM_SIZE_VERSION_3 0x80000000

/**
 * Yara Declarations
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
  declare_integer("signature");  // uint64_t to int64_t
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

  declare_integer_array("difat_sector_locations");
  declare_integer_array("difat");
  declare_integer_array("fat");

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
      declare_integer("data4");
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

end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

void expose_constants(YR_OBJECT* module_object)
{
  yr_set_integer(0, module_object, "is_ole");

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

typedef struct _COMPOUND_FILE
{
  PCOMPOUND_FILE_HEADER pHeader;
  DWORD dwSize;
  DWORD* pDifatLocations;
  DWORD dwNumberOfDifatLocations;
  DWORD* pDifat;
  DWORD dwNumberOfDifatEntries;
  DWORD* pFat;
  DWORD dwNumberOfFatEntries;
  PDIRECTORY_ENTRY* pDirectories;
  DWORD dwNumberOfDirectoryEntries;

} COMPOUND_FILE, *PCOMPOUND_FILE;

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

void parse_difat(PCOMPOUND_FILE pOle)
{
  // Compute the header difat and sector difat length
  DWORD dwHeaderDifatLength = sizeof(pOle->pHeader->difat) / sizeof(DWORD);
  DWORD dwSectorSize = 1 << yr_le16toh(pOle->pHeader->sector_shift);
  DWORD dwDifatSectorLength = (dwSectorSize / sizeof(DWORD)) - 1;

  // Allocate the required arrays, including for the ENDOFCHAIN
  DWORD dwNumberOfDifatSectors = yr_le32toh(
      pOle->pHeader->number_of_difat_sectors);
  DWORD dwNumberOfDifatLocations = dwNumberOfDifatSectors + 1;
  pOle->pDifatLocations = yr_calloc(dwNumberOfDifatLocations, sizeof(DWORD));

  DWORD dwNumberOfDifatEntries = dwHeaderDifatLength +
                                 dwNumberOfDifatSectors * dwDifatSectorLength;
  pOle->pDifat = yr_calloc(dwNumberOfDifatEntries, sizeof(DWORD));

  // Walk the header difat
  for (int i = 0; i < dwHeaderDifatLength; i++)
  {
    DWORD dwFatLocation = yr_le32toh(pOle->pHeader->difat[i]);
    pOle->pDifat[i] = dwFatLocation;
  }

  // Only loop number_of_difat_sectors sectors to avoid infinite loops and
  // ensure the next difat sector is within bounds
  DWORD dwDifatLocation = yr_le32toh(
      pOle->pHeader->first_difat_sector_location);

  for (int i = 0; i < dwNumberOfDifatSectors &&
                  dwDifatLocation != SECTOR_NUMBER_ENDOFCHAIN &&
                  dwSectorSize * (dwDifatLocation + 2) <= pOle->dwSize;
       i++)
  {
    // Update the difat locations
    pOle->dwNumberOfDifatLocations = i + 1;
    pOle->pDifatLocations[i] = dwDifatLocation;

    // Walk the difat sector
    DWORD* pDifat =
        (DWORD*) (((BYTE*) pOle->pHeader) + dwSectorSize * (dwDifatLocation + 1));

    for (int j = 0; j < dwDifatSectorLength; j++)
    {
      DWORD dwFatLocation = yr_le32toh(pDifat[j]);
      pOle->pDifat[dwHeaderDifatLength + (dwDifatSectorLength * i) + j] =
          dwFatLocation;
    }

    // Define next difat in chain
    dwDifatLocation = yr_le32toh(pDifat[dwDifatSectorLength]);
  }

  // Update the number of set difat entries
  pOle->dwNumberOfDifatEntries = dwHeaderDifatLength +
                                 pOle->dwNumberOfDifatLocations *
                                     dwDifatSectorLength;

  // Store the last difat location, which is expected to be an ENDOFCHAIN
  pOle->pDifatLocations[pOle->dwNumberOfDifatLocations] = dwDifatLocation;
  pOle->dwNumberOfDifatLocations++;
}

void parse_fat(PCOMPOUND_FILE pOle)
{
  // Compute the fat sector length
  DWORD dwSectorSize = 1 << yr_le16toh(pOle->pHeader->sector_shift);
  DWORD dwFatSectorLength = dwSectorSize / sizeof(DWORD);

  // Allocate the required arrays
  pOle->dwNumberOfFatEntries = 0;
  for (int i = 0; i < pOle->dwNumberOfDifatEntries &&
                  pOle->pDifat[i] <= SECTOR_NUMBER_MAXREGSECT;
       i++)
    pOle->dwNumberOfFatEntries += dwFatSectorLength;
  pOle->pFat = yr_calloc(pOle->dwNumberOfFatEntries, sizeof(DWORD));

  // Walk difat
  for (int i = 0; i < pOle->dwNumberOfDifatEntries &&
                  pOle->pDifat[i] <= SECTOR_NUMBER_MAXREGSECT &&
                  dwSectorSize * (pOle->pDifat[i] + 2) <= pOle->dwSize;
       i++)
  {
    // Walk fat
    DWORD dwFatLocation = pOle->pDifat[i];
    DWORD* pFat =
        (DWORD*) (((BYTE*) pOle->pHeader) + dwSectorSize * (dwFatLocation + 1));

    for (int j = 0; j < dwFatSectorLength; j++)
    {
      DWORD dwFatEntry = pFat[j];
      pOle->pFat[dwFatSectorLength * i + j] = dwFatEntry;
    }
  }
}

void parse_directories(PCOMPOUND_FILE pOle)
{
  DWORD dwSectorSize = 1 << yr_le16toh(pOle->pHeader->sector_shift);
  DWORD dwDirectorySectorLength = dwSectorSize / sizeof(DIRECTORY_ENTRY);

  // Number of Directory Sectors; If Major Version is 3, the Number of Directory
  // Sectors MUST be zero. This field is not supported for version 3 compound
  // files.
  bool bIsVersion3 = yr_le32toh(pOle->pHeader->version_major) ==
                     VERSION_MAJOR_3;
  DWORD dwNumberOfDirectorySectors =
      bIsVersion3 ? 0 : yr_le32toh(pOle->pHeader->number_of_directory_sectors);
  if (bIsVersion3)
  {
    for (DWORD dwDirectorySectorLocation =
             yr_le32toh(pOle->pHeader->first_directory_sector_location);
         dwNumberOfDirectorySectors <= SECTOR_NUMBER_MAXREGSECT &&
         dwDirectorySectorLocation <= SECTOR_NUMBER_MAXREGSECT &&
         dwDirectorySectorLocation < pOle->dwNumberOfFatEntries;
         dwDirectorySectorLocation = pOle->pFat[dwDirectorySectorLocation])
    {
      dwNumberOfDirectorySectors++;
    }
  }


  pOle->dwNumberOfDirectoryEntries = dwNumberOfDirectorySectors *
                                     dwDirectorySectorLength;
  pOle->pDirectories = yr_calloc(
      pOle->dwNumberOfDirectoryEntries, sizeof(PDIRECTORY_ENTRY));

  // Walk directory sectors
  DWORD dwDirectorySectorLocation = yr_le32toh(
      pOle->pHeader->first_directory_sector_location);
  for (int i = 0;
       i < dwNumberOfDirectorySectors &&
       dwDirectorySectorLocation <= SECTOR_NUMBER_MAXREGSECT &&
       dwSectorSize * (dwDirectorySectorLocation + 2) <= pOle->dwSize;
       i++)
  {
    PDIRECTORY_ENTRY pDirectoryEntries =
        (PDIRECTORY_ENTRY) (((BYTE*) pOle->pHeader) + dwSectorSize * (dwDirectorySectorLocation + 1));

    // Walk the directory entries
    for (int j = 0; j < dwDirectorySectorLength; j++)
    {
      PDIRECTORY_ENTRY pDirectoryEntry = &pDirectoryEntries[j];
      pOle->pDirectories[i * dwDirectorySectorLength + j] = pDirectoryEntry;
    }

    dwDirectorySectorLocation = pOle->pFat[dwDirectorySectorLocation];
  }
}

void expose_directories(YR_OBJECT* module_object, PCOMPOUND_FILE pOle)
{
  for (int i = 0; i < pOle->dwNumberOfDirectoryEntries; i++)
  {
    PDIRECTORY_ENTRY pDirectory = pOle->pDirectories[i];
    if (pDirectory == NULL)
      printf(
          "Fails at %d while there is support for %d\n",
          i,
          pOle->dwNumberOfDirectoryEntries);
    yr_set_sized_string(
        (const char*) pDirectory->name,
        pDirectory->name_length,
        module_object,
        "directories[%i].name",
        i);
    yr_set_integer(
        yr_le16toh(pDirectory->name_length),
        module_object,
        "directories[%i].name_length",
        i);
    yr_set_integer(
        pDirectory->object_type,
        module_object,
        "directories[%i].object_type",
        i);
    yr_set_integer(
        pDirectory->color_flag, module_object, "directories[%i].color_flag", i);
    yr_set_integer(
        yr_le32toh(pDirectory->left_sibling_id),
        module_object,
        "directories[%i].left_sibling_id",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->right_sibling_id),
        module_object,
        "directories[%i].right_sibling_id",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->child_id),
        module_object,
        "directories[%i].child_id",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->clsid.Data1),
        module_object,
        "directories[%i].clsid.data1",
        i);
    yr_set_integer(
        yr_le16toh(pDirectory->clsid.Data2),
        module_object,
        "directories[%i].clsid.data2",
        i);
    yr_set_integer(
        yr_le16toh(pDirectory->clsid.Data3),
        module_object,
        "directories[%i].clsid.data3",
        i);
    yr_set_integer(
        yr_le64toh(pDirectory->clsid.Data4),
        module_object,
        "directories[%i].clsid.data4",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->state_bits),
        module_object,
        "directories[%i].state_bits",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->creation_time.dwLowDateTime),
        module_object,
        "directories[%i].creation_time.low",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->creation_time.dwHighDateTime),
        module_object,
        "directories[%i].creation_time.high",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->modified_time.dwLowDateTime),
        module_object,
        "directories[%i].modified_time.low",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->modified_time.dwHighDateTime),
        module_object,
        "directories[%i].modified_time.high",
        i);
    yr_set_integer(
        yr_le32toh(pDirectory->starting_sector_location),
        module_object,
        "directories[%i].starting_sector_location",
        i);
    yr_set_integer(
        yr_le64toh(pDirectory->stream_size),
        module_object,
        "directories[%i].stream_size",
        i);
  }
}

void expose_fat(YR_OBJECT* module_object, PCOMPOUND_FILE pOle)
{
  for (int i = 0; i < pOle->dwNumberOfFatEntries; i++)
  {
    yr_set_integer(pOle->pFat[i], module_object, "fat[%i]", i);
  }
}

void expose_header(YR_OBJECT* module_object, PCOMPOUND_FILE pOle)
{
  PCOMPOUND_FILE_HEADER pHeader = pOle->pHeader;
  yr_set_integer(is_valid_header(pHeader), module_object, "is_ole");

  yr_set_integer(yr_le64toh(pHeader->signature), module_object, "signature");
  yr_set_integer(
      yr_le32toh(pHeader->clsid.Data1), module_object, "clsid.data1");
  yr_set_integer(
      yr_le16toh(pHeader->clsid.Data2), module_object, "clsid.data2");
  yr_set_integer(
      yr_le16toh(pHeader->clsid.Data3), module_object, "clsid.data3");
  yr_set_integer(
      yr_le64toh(pHeader->clsid.Data4), module_object, "clsid.data4");
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

void expose_difat(YR_OBJECT* module_object, PCOMPOUND_FILE pOle)
{
  for (int i = 0; i < pOle->dwNumberOfDifatLocations; i++)
  {
    yr_set_integer(
        pOle->pDifatLocations[i],
        module_object,
        "difat_sector_locations[%i]",
        i);
  }
  for (int i = 0; i < pOle->dwNumberOfDifatEntries; i++)
  {
    yr_set_integer(pOle->pDifat[i], module_object, "difat[%i]", i);
  }
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  PCOMPOUND_FILE_HEADER pHeader;

  expose_constants(module_object);

  foreach_memory_block(iterator, block)
  {
    // Make sure the header is at least large enough
    pHeader = (PCOMPOUND_FILE_HEADER) block->fetch_data(block);

    if (pHeader == NULL || block->size < sizeof(COMPOUND_FILE_HEADER))
      continue;

    // Allocate a compound file
    PCOMPOUND_FILE pOle = yr_calloc(1, sizeof(COMPOUND_FILE));
    module_object->data = pOle;
    pOle->pHeader = pHeader;
    pOle->dwSize = block->size;

    // Only parse the compound file if the header is valid
    if (is_valid_header(pHeader))
    {
      parse_difat(pOle);
      expose_difat(module_object, pOle);
      parse_fat(pOle);
      expose_fat(module_object, pOle);
      parse_directories(pOle);
      expose_directories(module_object, pOle);
    }

    // Expose the header as it was valid
    expose_header(module_object, pOle);
    break;
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  PCOMPOUND_FILE pOle = module_object->data;
  if (pOle != NULL)
  {
    if (pOle->pDifat != NULL)
      yr_free(pOle->pDifat);
    if (pOle->pDifatLocations != NULL)
      yr_free(pOle->pDifatLocations);
    if (pOle->pFat != NULL)
      yr_free(pOle->pFat);
    if (pOle->pDirectories != NULL)
      yr_free(pOle->pDirectories);
  }
  yr_free(pOle);
  return ERROR_SUCCESS;
}

#pragma clang diagnostic pop