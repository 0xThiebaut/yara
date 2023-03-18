
.. _cfb-module:

#########
CFB module
#########

The CFB module allows you to create more fine-grained rules for Compound File Binary files by
using attributes and features of the Compound File Binary file format. This module exposes all of
the fields present in a CFB header and provides functions which can be used to
write more expressive and targeted rules. Let's see some examples:

.. code-block:: yara

    import "cfb"


    rule suspicious_msi_executing_dll {
        meta:
            description = "Detects suspicious MSI files where the CustomAction table only executes a DLL while ignoring its exit code (Type 0x41)"

        condition:
            // An MSI is a Compound File Binary
            cfb.is_cfb and
            // Where the first directory is the "Root Entry" (wide)
            cfb.directories[0].name == "R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y\x00" and
            // And the CLSID is 000C1084-0000-0000-C000-000000000046
            cfb.directories[0].clsid.data1 == 0x0C1084 and cfb.directories[0].clsid.data2 == 0x0 and cfb.directories[0].clsid.data3 == 0x0 and
            cfb.directories[0].clsid.data4[0] == 0xC0 and
            cfb.directories[0].clsid.data4[1] == 0x0 and
            cfb.directories[0].clsid.data4[2] == 0x0 and
            cfb.directories[0].clsid.data4[3] == 0x0 and
            cfb.directories[0].clsid.data4[4] == 0x0 and
            cfb.directories[0].clsid.data4[5] == 0x0 and
            cfb.directories[0].clsid.data4[6] == 0x0 and
            cfb.directories[0].clsid.data4[7] == 0x46 and
            // Where any of the streams is a likely executable
            for any i in (0..cfb.number_of_directories) : (cfb.int16_at(i, 0) == 0x4D5A) and
            // And the CustomAction table only contains a DLL execution (0x1) while ignoring its exit code (0x40)
            for any i in (0..cfb.number_of_directories) : (
                cfb.directories[i].name == "\x40\x48\x0c\x46\xf6\x45\x32\x44\x8a\x41\x37\x43\x72\x44" and
                cfb.directories[i].stream_size == 0xC and
                cfb.int8_at(i, 2) == 0x41
            )
    }

Reference
---------

.. c:type:: is_cfb

    Return true if the file is a Compound File Binary.

     *Example: cfb.is_cfb*

.. c:type:: signature

    Integer containing the header's signature which, for a valid CFB, must be:

    .. c:type:: HEADER_SIGNATURE

        The Compound File Binary header's signature of value `0xE11AB1A1E011CFD0`.
        Do note that as an `int64`, this value represents `-2226271756974174256` rather than the expected `uint64` representation of `16220472316735377360`.

    *Example: cfb.signature == cfb.HEADER_SIGNATURE*

.. c:type:: clsid

    Structure containing information about the CFB header's CLSID which, for a valid CFB, should be reserved and all zeroes.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/49e490b8-f972-45d6-a3a4-99f924998d97

    .. c:member:: data1

        An opaque value equivalent to the `time_low` field of RFC 4122.

    .. c:member:: data2

        An opaque value equivalent to the `time_mid` field of RFC 4122.

    .. c:member:: data3

        An opaque value equivalent to the `time_hi_and_version` field of RFC 4122.

    .. c:member:: data4

        A sequence (array) of 8 opaque values equivalent to the `clock_seq_hi_and_reserved`, `clock_seq_low` and `node` fields of RFC 4122.

.. c:type:: version_major

    Version number for breaking changes. This field MUST be set to either one of:

    .. c:type:: VERSION_MAJOR_3

        The Compound File Binary v3 major version of value `0x0003`.

    .. c:type:: VERSION_MAJOR_4

        The Compound File Binary v4 major version of value `0x0004`.

    *Example: cfb.version_major == cfb.VERSION_MAJOR_3*

.. c:type:: version_minor

    Integer containing the version number for nonbreaking changes.
    If the `major_version` field is either `VERSION_MAJOR_3` or `VERSION_MAJOR_4`, this field SHOULD be set to:

    .. c:type:: VERSION_MINOR

        The Compound File Binary v3 or v4 minor version of value `0x003E`.

    *Example: cfb.version_minor == cfb.VERSION_MINOR*

.. c:type:: byte_order

    Integer containing the byte order mark for all integer fields.
    This field MUST be set to:

    .. c:type:: BYTE_ORDER_LITTLE_ENDIAN

        The little-endian byte order mark of value `0xFFFE`.

    *Example: cfb.byte_order == cfb.BYTE_ORDER_LITTLE_ENDIAN*

.. c:type:: sector_shift

    Integer specifying the sector size of the compound file as a power of 2.
    This field MUST be set to either one of:

    .. c:type:: SECTOR_SHIFT_VERSION_3

        A value of `0x0009` indicating a sector size of `512` for a `version_major` of value `VERSION_MAJOR_3`.

    .. c:type:: SECTOR_SHIFT_VERSION_4

        A value of `0x000C` indicating a sector size of `4096` for a `version_major` of value `VERSION_MAJOR_4`.

    *Example: cfb.sector_shift == cfb.SECTOR_SHIFT_VERSION_3*

.. c:type:: mini_sector_shift

    Integer specifying the sector size of the mini stream as a power of 2. This field MUST be set to:

    .. c:type:: MINI_SECTOR_SHIFT

        A value of `0x0006` indicating a sector size of `64` for the mini stream.

    *Example: cfb.mini_sector_shift == cfb.mini_sector_shift*

.. c:type:: reserved

    An byte array of length 8 which MUST be set to all zeroes (`0`).

    *Example: cfb.reserved[0] == 0*

.. c:type:: number_of_directory_sectors

    An integer containing the number of directory sectors in the compound file.
    If `version_major` is `SECTOR_SHIFT_VERSION_3`, the number MUST be set to:

    .. c:type:: NUMBER_OF_DIRECTORY_SECTORS_VERSION_3

        A value of `0x0000` indicating the field is not supported for version 3 compound files.

    *Example: cfb.number_of_directory_sectors == cfb.NUMBER_OF_DIRECTORY_SECTORS_VERSION_3*

.. c:type:: number_of_fat_sectors

    An integer containing the number of FAT sectors in the compound file.

    *Example: cfb.number_of_directory_sectors == 0*

.. c:type:: first_directory_sector_location

    An integer containing the starting sector number for the directory stream.

    *Example: cfb.first_directory_sector_location <= cfb.SECTOR_NUMBER_MAXREGSECT*

.. c:type:: transaction_signature

    An integer which MAY contain a sequence number that is incremented every time the compound file is saved by an
    implementation that supports file transactions.
    This is the field that MUST be set to all zeroes if file transactions are not implemented.

    *Example: cfb.transaction_signature == 0*

.. c:type:: mini_stream_cutoff_size

    An integer specifying the maximum size of a user-defined data stream that is allocated from the mini FAT
    and mini stream. Any user-defined data stream that is greater than or equal to this cutoff size must be
    allocated as normal sectors from the FAT. his integer field MUST be set to:

    .. c:type:: MINI_STREAM_CUTOFF_SIZE

        A value of `0x00001000` indicating a maximum size of `4096` bytes for user-defined data stream that are
        allocated from the mini FAT and mini stream.

    *Example: cfb.mini_stream_cutoff_size == cfb.MINI_STREAM_CUTOFF_SIZE*

.. c:type:: first_mini_fat_sector_location

    An integer containing the starting sector number of the mini FAT.

    *Example: cfb.first_mini_fat_sector_location <= cfb.SECTOR_NUMBER_MAXREGSECT*

.. c:type:: number_of_mini_fat_sectors

    An integer containing the number of mini FAT sectors in the compound file.

    *Example: cfb.number_of_mini_fat_sectors == 0*

.. c:type:: first_difat_sector_location

    An integer containing the starting sector number of the DIFAT.

    *Example: cfb.first_difat_sector_location <= cfb.SECTOR_NUMBER_MAXREGSECT*

.. c:type:: number_of_difat_sectors

    An integer containing the number of DIFAT sectors in the compound file.

    *Example: cfb.number_of_difat_sectors == 0*

.. c:type:: difat_sector_locations

    A computed array of integers containing the sector numbers of the DIFAT sectors in the compound file,
    including the terminating `SECTOR_NUMBER_ENDOFCHAIN`.

    *Example: cfb.difat_sector_locations[cfb.number_of_difat_sectors] == cfb.SECTOR_NUMBER_ENDOFCHAIN*

.. c:type:: difat

    A computed array of integers containing the sector numbers of the FAT sectors in the compound file.

    *Example: cfb.difat[0] <= cfb.SECTOR_NUMBER_MAXREGSECT*

.. c:type:: fat

    The set of FAT sectors can be considered together as a single integer array. Each entry in that array contains
    the sector number of the next sector in the chain, and this sector number can be used as an index into
    the FAT array to continue along the chain. Special values are:

    .. c:type:: SECTOR_NUMBER_MAXREGSECT

        A value of `0xFFFFFFFA` indicating a maximum valid (inclusive) sector location.
        Any sector location above this value is a special value.

    .. c:type:: SECTOR_NUMBER_DIFSECT

        A value of `0xFFFFFFFC` indicating the sector is reserved as a DIFAT sector.

    .. c:type:: SECTOR_NUMBER_FATSECT

        A value of `0xFFFFFFFD` indicating the sector is reserved as a FAT sector.

    .. c:type:: SECTOR_NUMBER_ENDOFCHAIN

        A value of `0xFFFFFFFE` indicating the sector was the last of its chain.

    .. c:type:: SECTOR_NUMBER_FREESECT

        A value of `0xFFFFFFFF` indicating the sector is allocated and free.

    *Example: cfb.fat[cfb.first_difat_sector_location] == cfb.SECTOR_NUMBER_DIFSECT*

.. c:type:: mini_fat_sector_locations

    A computed array of integers containing the sector numbers of the mini FAT sectors in the compound file,
    including the terminating `SECTOR_NUMBER_ENDOFCHAIN`.

    *Example: cfb.mini_fat_sector_locations[cfb.number_of_mini_fat_sectors] == cfb.SECTOR_NUMBER_ENDOFCHAIN*

.. c:type:: mini_fat

    The set of mini FAT sectors can be considered together as a single integer array. Each entry in that array contains
    the sector number of the next sector in the mini stream, and this sector number can be used as an offset into
    the mini stream to continue along the chain. Special values are:

    .. c:type:: SECTOR_NUMBER_ENDOFCHAIN

        A value of `0xFFFFFFFE` indicating the sector was the last of its chain.

    .. c:type:: SECTOR_NUMBER_FREESECT

        A value of `0xFFFFFFFF` indicating the sector is allocated and free.

    *Example: cfb.mini_fat[0] != cfb.SECTOR_NUMBER_FREESECT*

.. c:type:: number_of_directories

    A computed integer containing the number of directory entries in the compound file.

    *Example: cfb.number_of_directories > 0*

.. c:type:: directories

    An array of directory entries, each one with the following properties:

    .. c:type:: name

        A UTF-8 string that MUST contain a Unicode string for the storage or stream name encoded in UTF-16.
        While the specification requires the name to be terminated with a UTF-16 terminating null character,
        this field omits this null character. This field is hence only set if the directory is
        allocated (`object_type != OBJECT_TYPE_UNALLOCATED`), the `name_length` (incl. terminating null character) is
        within the `2 <= name_length <= 64` range and the `name` has a UTF-16 terminating null character.

        The following characters are illegal and MUST NOT be part of the name: `/`, `\\`, `:`, `!`.

    .. c:type:: name_length

        An integer matching the length of the `name` Unicode string in bytes.
        The length MUST be a multiple of `2` and includes the terminating null character in the count.
        This length MUST NOT exceed `64`, the maximum size of the Directory Entry `name` field.

        As this field includes the terminating UTF-16 null character, the `name_length` equals the length of the `name`
        field incremented by `2`.

.. c:function:: rva_to_offset(addr)

    Function returning the file offset for RVA *addr*. Be careful to pass
    relative addresses here and not absolute addresses, like `pe.entry_point`
    when scanning a process.

    *Example: pe.rva_to_offset(pe.sections[0].virtual_address) == pe.sections[0].raw_data_offset*

    This example will make sure the offset for the virtual address in the first
    section equals the file offset for that section.
