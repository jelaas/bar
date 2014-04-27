#ifndef BAR_RPM_H
#define BAR_RPM_H

#include <sys/types.h>
#include <unistd.h>

/* http://rpm.org/max-rpm/s1-rpm-file-format-rpm-file-format.html */

#define RPMMAGIC 0xedabeedb
struct rpmlead {
	uint32_t magic;
//	unsigned char magic[4];
	unsigned char major, minor;
	short type;
	short archnum;
	char name[66];
	short osnum;
	short signature_type;
	char reserved[16];
};

#define RPMSIGTYPE_HEADERSIG 5

struct canon {
  const char *name;
};

#define OSNUM_LINUX 1
#define OSNUM_IRIX 2
#define OSNUM_SOLARIS 3
#define OSNUM_SUNOS 4
#define OSNUM_AIX 5
#define OSNUM_HPUX10 6
#define OSNUM_OSF1 7
#define OSNUM_FREEBSD 8
#define OSNUM_SCO 9
#define OSNUM_IRIX64 10
#define OSNUM_NEXTSTEP 11
#define OSNUM_BSDI 12
#define OSNUM_MACHTEN 13
#define OSNUM_CYGWIN32_NT 14
#define OSNUM_CYGWIN32_95 15
#define OSNUM_MP_RAS 16
#define OSNUM_MINT 17
#define OSNUM_OS390 18
#define OSNUM_VM_ESA 19
#define OSNUM_LINUX_390 20
#define OSNUM_MACOSX 21

#define OSNUM__MAX 21

#define ARCHNUM_X86 1
#define ARCHNUM_ALPHA 2
#define ARCHNUM_SPARC 3
#define ARCHNUM_MIPS 4
#define ARCHNUM_PPC 5
#define ARCHNUM_M68K 6
#define ARCHNUM_SGI 7
#define ARCHNUM_RS6000 8
#define ARCHNUM_IA64 9
#define ARCHNUM_MIPSEL 11
#define ARCHNUM_ARM 12
#define ARCHNUM_M68KMINT 13
#define ARCHNUM_S390 14
#define ARCHNUM_S390X 15
#define ARCHNUM_PPC64 16
#define ARCHNUM_SH 17
#define ARCHNUM_XTENSA 18

#define ARCHNUM__MAX 18

#define HEADERMAGIC 0x8eade8
struct header {
	uint32_t magic;
	uint32_t reserved;
	uint32_t entries;
	uint32_t size;
};

#define HDRTYPE_NULL 0
#define HDRTYPE_CHAR 1
#define HDRTYPE_INT8 2
#define HDRTYPE_INT16 3
#define HDRTYPE_INT32 4
#define HDRTYPE_INT64 5
#define HDRTYPE_STRING 6
#define HDRTYPE_BIN 7
#define HDRTYPE_STRARRAY 8
#define HDRTYPE_I18NSTRING 9

#define SIGTAG_HEADERSIGNATURES 62
#define SIGTAG_RSA           268
#define SIGTAG_SHA1          269
#define SIGTAG_SIZE         1000
#define SIGTAG_LEMD5_1      1001
#define SIGTAG_PGP          1002
#define SIGTAG_MD5          1004
#define SIGTAG_PAYLOADSIZE  1007

struct indexentry {
	uint32_t tag;
	uint32_t type;
	uint32_t offset;
	uint32_t count;
};

#define RPMTAG_HEADERI18NTABLE           100
#define RPMTAG_NAME                     1000
#define RPMTAG_VERSION                  1001
#define RPMTAG_RELEASE                  1002
#define RPMTAG_SERIAL                   1003
#define RPMTAG_SUMMARY                  1004
#define RPMTAG_DESCRIPTION              1005
#define RPMTAG_BUILDTIME                1006
#define RPMTAG_BUILDHOST                1007
#define RPMTAG_INSTALLTIME              1008
#define RPMTAG_SIZE                     1009
#define RPMTAG_DISTRIBUTION             1010
#define RPMTAG_VENDOR                   1011
#define RPMTAG_GIF                      1012
#define RPMTAG_XPM                      1013
#define RPMTAG_COPYRIGHT                1014
#define RPMTAG_PACKAGER                 1015
#define RPMTAG_GROUP                    1016
#define RPMTAG_CHANGELOG                1017
#define RPMTAG_SOURCE                   1018
#define RPMTAG_PATCH                    1019
#define RPMTAG_URL                      1020
#define RPMTAG_OS                       1021
#define RPMTAG_ARCH                     1022
#define RPMTAG_PREIN                    1023
#define RPMTAG_POSTIN                   1024
#define RPMTAG_PREUN                    1025
#define RPMTAG_POSTUN                   1026
#define RPMTAG_FILENAMES                1027
#define RPMTAG_FILESIZES                1028
#define RPMTAG_FILESTATES               1029
#define RPMTAG_FILEMODES                1030
#define RPMTAG_FILEUIDS                 1031
#define RPMTAG_FILEGIDS                 1032
#define RPMTAG_FILERDEVS                1033
#define RPMTAG_FILEMTIMES               1034
#define RPMTAG_FILEMD5S                 1035
#define RPMTAG_FILELINKTOS              1036
#define RPMTAG_FILEFLAGS                1037
#define RPMTAG_ROOT                     1038
#define RPMTAG_FILEUSERNAME             1039
#define RPMTAG_FILEGROUPNAME            1040
#define RPMTAG_EXCLUDE                  1041 /* not used */
#define RPMTAG_EXCLUSIVE                1042 /* not used */
#define RPMTAG_ICON                     1043
#define RPMTAG_SOURCERPM                1044
#define RPMTAG_FILEVERIFYFLAGS          1045
#define RPMTAG_ARCHIVESIZE              1046
#define RPMTAG_PROVIDES                 1047
#define RPMTAG_REQUIREFLAGS             1048
#define RPMTAG_REQUIRENAME              1049
#define RPMTAG_REQUIREVERSION           1050
#define RPMTAG_NOSOURCE                 1051
#define RPMTAG_NOPATCH                  1052
#define RPMTAG_CONFLICTFLAGS            1053
#define RPMTAG_CONFLICTNAME             1054
#define RPMTAG_CONFLICTVERSION          1055
#define RPMTAG_DEFAULTPREFIX            1056
#define RPMTAG_BUILDROOT                1057
#define RPMTAG_INSTALLPREFIX            1058
#define RPMTAG_EXCLUDEARCH              1059
#define RPMTAG_EXCLUDEOS                1060
#define RPMTAG_EXCLUSIVEARCH            1061
#define RPMTAG_EXCLUSIVEOS              1062
#define RPMTAG_AUTOREQPROV              1063 /* used internally by build */
#define RPMTAG_RPMVERSION               1064
#define RPMTAG_TRIGGERSCRIPTS           1065
#define RPMTAG_TRIGGERNAME              1066
#define RPMTAG_TRIGGERVERSION           1067
#define RPMTAG_TRIGGERFLAGS             1068
#define RPMTAG_TRIGGERINDEX             1069
#define RPMTAG_VERIFYSCRIPT             1079
#define RPMTAG_CHANGELOGTIME            1080 /* i[] */
#define RPMTAG_CHANGELOGNAME            1081 /* s[] */
#define RPMTAG_CHANGELOGTEXT            1082 /* s[] */
#define RPMTAG_BROKENMD5                1083 /* internal - obsolete */
#define RPMTAG_PREREQ                1084 /* internal */
#define RPMTAG_PREINPROG             1085 /* s */
#define RPMTAG_POSTINPROG            1086 /* s */
#define RPMTAG_PREUNPROG             1087 /* s */
#define RPMTAG_POSTUNPROG            1088 /* s */
#define RPMTAG_BUILDARCHS            1089 /* s[] */
#define RPMTAG_OBSOLETENAME          1090 /* s[] */
#define RPMTAG_VERIFYSCRIPTPROG      1091 /* s */
#define RPMTAG_TRIGGERSCRIPTPROG     1092 /* s[] */
#define RPMTAG_DOCDIR                1093 /* internal */
#define RPMTAG_COOKIE                1094 /* s */
#define RPMTAG_FILEDEVICES           1095 /* i[] */
#define RPMTAG_FILEINODES            1096 /* i[] */
#define RPMTAG_FILELANGS             1097 /* s[] */
#define RPMTAG_PREFIXES              1098 /* s[] */
#define RPMTAG_INSTPREFIXES          1099 /* s[] */
#define RPMTAG_TRIGGERIN             1100 /* internal */
#define RPMTAG_TRIGGERUN             1101 /* internal */
#define RPMTAG_TRIGGERPOSTUN         1102 /* internal */
#define RPMTAG_AUTOREQ               1103 /* internal */
#define RPMTAG_AUTOPROV              1104 /* internal */
#define RPMTAG_CAPABILITY            1105 /* i legacy - obsolete */
#define RPMTAG_SOURCEPACKAGE         1106 /* i legacy - obsolete */
#define RPMTAG_OLDORIGFILENAMES      1107 /* internal - obsolete */
#define RPMTAG_BUILDPREREQ           1108 /* internal */
#define RPMTAG_BUILDREQUIRES         1109 /* internal */
#define RPMTAG_BUILDCONFLICTS        1110 /* internal */
#define RPMTAG_BUILDMACROS           1111 /* internal - unused */
#define RPMTAG_PROVIDEFLAGS          1112 /* i[] */
#define RPMTAG_PROVIDEVERSION        1113 /* s[] */
#define RPMTAG_OBSOLETEFLAGS         1114 /* i[] */
#define RPMTAG_OBSOLETEVERSION       1115 /* s[] */
#define RPMTAG_DIRINDEXES            1116 /* i[] */
#define RPMTAG_BASENAMES             1117 /* s[] */
#define RPMTAG_DIRNAMES              1118 /* s[] */
#define RPMTAG_ORIGDIRINDEXES        1119 /* i[] relocation */
#define RPMTAG_ORIGBASENAMES         1120 /* s[] relocation */
#define RPMTAG_ORIGDIRNAMES          1121 /* s[] relocation */
#define RPMTAG_OPTFLAGS              1122 /* s */
#define RPMTAG_DISTURL               1123 /* s */
#define RPMTAG_PAYLOADFORMAT         1124/* s */
#define RPMTAG_PAYLOADCOMPRESSOR     1125 /* s */
#define RPMTAG_PAYLOADFLAGS          1126 /* s */
#define RPMTAG_INSTALLCOLOR          1127 /* i transaction color when installed */
#define RPMTAG_INSTALLTID            1128 /* i */
#define RPMTAG_REMOVETID             1129 /* i */
#define RPMTAG_SHA1RHN               1130 /* internal - obsolete */
#define RPMTAG_RHNPLATFORM           1131 /* s deprecated */
#define RPMTAG_PLATFORM              1132 /* s */
#define RPMTAG_PATCHESNAME           1133 /* s[] deprecated placeholder (SuSE) */
#define RPMTAG_PATCHESFLAGS          1134 /* i[] deprecated placeholder (SuSE) */
#define RPMTAG_PATCHESVERSION        1135 /* s[] deprecated placeholder (SuSE) */
#define RPMTAG_CACHECTIME            1136 /* i internal - obsolete */
#define RPMTAG_CACHEPKGPATH          1137 /* s internal - obsolete */
#define RPMTAG_CACHEPKGSIZE          1138 /* i internal - obsolete */
#define RPMTAG_CACHEPKGMTIME         1139 /* i internal - obsolete */
#define RPMTAG_FILECOLORS            1140 /* i[] */
#define RPMTAG_FILECLASS             1141 /* i[] */
#define RPMTAG_CLASSDICT             1142 /* s[] */
#define RPMTAG_FILEDEPENDSX          1143 /* i[] */
#define RPMTAG_FILEDEPENDSN          1144 /* i[] */
#define RPMTAG_DEPENDSDICT           1145
#define RPMTAG_FILEDIGESTALGO        5011

struct tag {
	int tag;
	int type;
	int track;
	int count;
	int size;
	char *value;
};

struct rpm {
	struct rpmlead lead;
	struct header sig;
	struct jlhead *sigtags;
	struct header header;
	struct jlhead *tags;
	off_t headeroffset;
	off_t payloadoffset;
	off_t eofoffset;
	size_t uncompressed_size;
	size_t sumsize;

	char *compressor, *digestalgo;
	
	/* offsets to sigtag values that can only be written after the whole payload is generated */
	off_t sigtag_md5sum;
	off_t sigtag_size;	
	off_t sigtag_payloadsize;

	/* offsets within header */
	off_t rpmtag_size;
};

struct bar_options {
  int info,pkginfo,sync,list;
  int ignore_chksum;
  int printtag;
  char *prefix;
  char *cwd;
};

struct rpm *rpm_new();

#endif
