/*
 * The platform dance PKCS #11 requires of every caller.
 *
 * OASIS ships pkcs11.h without the macros that say what a pointer looks like on
 * this platform — by design, because the same headers describe Win32 calling
 * conventions and Unix ones. Every consumer defines the six macros below before
 * including it. These are the Unix/macOS values.
 *
 * Vendored rather than depended on: the headers are a specification artefact
 * that changes every few years, not a library, and having them in the tree means
 * `swift build` needs nothing installed.
 *
 * Source: OASIS PKCS #11 v3.0 (pkcs11.h, pkcs11t.h, pkcs11f.h), distributed
 * under the OASIS IPR Policy — see the notice at the top of each file.
 */

#ifndef CPKCS11_H
#define CPKCS11_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/*
 * Errata in the published v3.0 headers. pkcs11t.h declares CK_HKDF_PARAMS with
 * fields of type CK_HANDLE and CK_BOOL, and the specification defines neither
 * anywhere — the intended types are plainly CK_OBJECT_HANDLE and CK_BBOOL.
 * Nothing here uses HKDF, but the struct is parsed all the same, so the headers
 * do not compile at all without these.
 *
 * Macros rather than typedefs, because each has to resolve at its point of use
 * — halfway through pkcs11t.h — where a typedef written here would come too
 * early to name anything. CK_ULONG is what CK_OBJECT_HANDLE is a typedef of, so
 * the widths are the intended ones.
 *
 * Defined here rather than by editing the vendored files: those stay byte-for-
 * byte as OASIS published them, so re-downloading them is a diff of nothing.
 */
#define CK_HANDLE CK_ULONG
#define CK_BOOL CK_BBOOL

#include "pkcs11.h"

#endif /* CPKCS11_H */
