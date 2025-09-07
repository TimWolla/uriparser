/*
 * uriparser - RFC 3986 URI parsing library
 *
 * Copyright (C) 2025, Sebastian Pipping <sebastian@pipping.org>
 * All rights reserved.
 *
 * Redistribution and use in source  and binary forms, with or without
 * modification, are permitted provided  that the following conditions
 * are met:
 *
 *     1. Redistributions  of  source  code   must  retain  the  above
 *        copyright notice, this list  of conditions and the following
 *        disclaimer.
 *
 *     2. Redistributions  in binary  form  must  reproduce the  above
 *        copyright notice, this list  of conditions and the following
 *        disclaimer  in  the  documentation  and/or  other  materials
 *        provided with the distribution.
 *
 *     3. Neither the  name of the  copyright holder nor the  names of
 *        its contributors may be used  to endorse or promote products
 *        derived from  this software  without specific  prior written
 *        permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND  ANY EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT
 * LIMITED TO,  THE IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS
 * FOR  A  PARTICULAR  PURPOSE  ARE  DISCLAIMED.  IN  NO  EVENT  SHALL
 * THE  COPYRIGHT HOLDER  OR CONTRIBUTORS  BE LIABLE  FOR ANY  DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO,  PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA,  OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT  LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE  OR  OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file UriSetHostCommon.c
 * Holds code used by multiple SetHost* functions.
 * NOTE: This source file includes itself twice.
 */

/* What encodings are enabled? */
#include <uriparser/UriDefsConfig.h>
#if (!defined(URI_PASS_ANSI) && !defined(URI_PASS_UNICODE))
/* Include SELF twice */
# ifdef URI_ENABLE_ANSI
#  define URI_PASS_ANSI 1
#  include "UriSetHostCommon.c"
#  undef URI_PASS_ANSI
# endif
# ifdef URI_ENABLE_UNICODE
#  define URI_PASS_UNICODE 1
#  include "UriSetHostCommon.c"
#  undef URI_PASS_UNICODE
# endif
#else
# ifdef URI_PASS_ANSI
#  include <uriparser/UriDefsAnsi.h>
# else
#  include <uriparser/UriDefsUnicode.h>
#  include <wchar.h>
# endif



#ifndef URI_DOXYGEN
# include <uriparser/Uri.h>
# include <uriparser/UriIp4.h>
# include "UriCommon.h"
# include "UriMemory.h"
# include "UriSetHostBase.h"
# include "UriSetHostCommon.h"
#endif



#include <assert.h>



int URI_FUNC(InternalSetHostMm)(URI_TYPE(Uri) * uri,
		UriHostType hostType,
		const URI_CHAR * first,
		const URI_CHAR * afterLast,
		UriMemoryManager * memory) {
	/* Superficial input validation (before making any changes) */
	if ((uri == NULL) || ((first == NULL) != (afterLast == NULL))) {
		return URI_ERROR_NULL;
	}

	URI_CHECK_MEMORY_MANAGER(memory);  /* may return */

	/* The RFC 3986 grammar reads:
	 *   authority = [ userinfo "@" ] host [ ":" port ]
	 * So no user info or port without a host. */
	if (first == NULL) {
		if (uri->userInfo.first != NULL) {
			return URI_ERROR_SETHOST_USERINFO_SET;
		} else if (uri->portText.first != NULL) {
			return URI_ERROR_SETHOST_PORT_SET;
		}
	}

	/* Syntax-check the new value */
	if (first != NULL) {
		switch (hostType) {
			case URI_HOST_TYPE_IP4:
				if (URI_FUNC(IsWellFormedHostIp4)(first, afterLast) == URI_FALSE) {
					return URI_ERROR_SYNTAX;
				}
				break;
			case URI_HOST_TYPE_IP6:
				{
					const int res = URI_FUNC(IsWellFormedHostIp6Mm)(first, afterLast, memory);
					assert((res == URI_SUCCESS) || (res == URI_ERROR_SYNTAX) || (res == URI_ERROR_MALLOC));
					if (res != URI_SUCCESS) {
						return res;
					}
				}
				break;
			case URI_HOST_TYPE_IPFUTURE:
				{
					const int res = URI_FUNC(IsWellFormedHostIpFutureMm)(first, afterLast, memory);
					assert((res == URI_SUCCESS) || (res == URI_ERROR_SYNTAX) || (res == URI_ERROR_MALLOC));
					if (res != URI_SUCCESS) {
						return res;
					}
				}
				break;
			case URI_HOST_TYPE_REGNAME:
				if (URI_FUNC(IsWellFormedHostRegName)(first, afterLast) == URI_FALSE) {
					return URI_ERROR_SYNTAX;
				}
				break;
			default:
				assert(0 && "Unsupported URI host type");
		}
	}

	/* Ensure owned */
	if ((first != NULL) && (uri->owner == URI_FALSE)) {
		const int res = URI_FUNC(MakeOwnerMm)(uri, memory);
		if (res != URI_SUCCESS) {
			return res;
		}
	}

	/* Apply new value; NOTE that .hostText is set for all four host types */
	{
		URI_TYPE(Uri) oldUri = *uri;

		uri->hostText.first = NULL;
		uri->hostText.afterLast = NULL;
		uri->hostData.ipFuture.first = NULL;
		uri->hostData.ipFuture.afterLast = NULL;
		uri->hostData.ip4 = NULL;
		uri->hostData.ip6 = NULL;

		if (first == NULL) {
			if (URI_FUNC(HasHost)(&oldUri)) {
				uri->absolutePath = URI_TRUE;

				if (URI_FUNC(EnsureThatPathIsNotMistakenForHost)(uri, memory) == URI_FALSE) {
					/* Restore original value */
					uri->hostText = oldUri.hostText;
					uri->hostData = oldUri.hostData;
					uri->absolutePath = oldUri.absolutePath;

					return URI_ERROR_MALLOC;
				}
			}
		} else {
			URI_TYPE(TextRange) sourceRange;
			sourceRange.first = first;
			sourceRange.afterLast = afterLast;

			if (URI_FUNC(CopyRangeAsNeeded)(&uri->hostText, &sourceRange, memory) == URI_FALSE) {
				/* Restore original value */
				uri->hostText = oldUri.hostText;
				uri->hostData = oldUri.hostData;

				return URI_ERROR_MALLOC;
			}

			/* Fill .hostData as needed */
			switch (hostType) {
				case URI_HOST_TYPE_IP4:
					{
						uri->hostData.ip4 = memory->malloc(memory, sizeof(UriIp4));
						if (uri->hostData.ip4 == NULL) {
							memory->free(memory, (URI_CHAR *)uri->hostText.first);
							/* Restore original value */
							uri->hostText = oldUri.hostText;
							uri->hostData = oldUri.hostData;

							return URI_ERROR_MALLOC;
						}

						{
							const int res = URI_FUNC(ParseIpFourAddress)(uri->hostData.ip4->data, first, afterLast);
#if defined(NDEBUG)
							(void)res;  /* i.e. mark as unused */
#else
							assert(res == URI_SUCCESS);  /* because checked for well-formedness earlier */
#endif
						}
					}
					break;
				case URI_HOST_TYPE_IP6:
					{
						uri->hostData.ip6 = memory->malloc(memory, sizeof(UriIp6));
						if (uri->hostData.ip6 == NULL) {
							memory->free(memory, (URI_CHAR *)uri->hostText.first);
							/* Restore original value */
							uri->hostText = oldUri.hostText;
							uri->hostData = oldUri.hostData;

							return URI_ERROR_MALLOC;
						}

						{
							const int res = URI_FUNC(ParseIpSixAddressMm)(uri->hostData.ip6, first, afterLast, memory);
							assert((res == URI_SUCCESS) || (res == URI_ERROR_MALLOC));  /* because checked for well-formedness earlier */
							if (res != URI_SUCCESS) {
								memory->free(memory, (URI_CHAR *)uri->hostText.first);
								/* Restore original value */
								uri->hostText = oldUri.hostText;
								uri->hostData = oldUri.hostData;

								return res;
							}
						}
					}
					break;
				case URI_HOST_TYPE_IPFUTURE:
					uri->hostData.ipFuture.first = uri->hostText.first;
					uri->hostData.ipFuture.afterLast = uri->hostText.afterLast;
					break;
				case URI_HOST_TYPE_REGNAME:
					break;
				default:
					assert(0 && "Unsupported URI host type");
			}

			uri->absolutePath = URI_FALSE;  /* always URI_FALSE for URIs with host  */
		}

		/* Clear old value */
		if (oldUri.hostData.ipFuture.first != NULL) {
			/* NOTE: .hostData.ipFuture holds the very same range pointers
			 *       as .hostText; we must not free memory twice. */
			oldUri.hostText.first = NULL;
			oldUri.hostText.afterLast = NULL;

			if ((oldUri.owner == URI_TRUE) && (oldUri.hostData.ipFuture.first != oldUri.hostData.ipFuture.afterLast)) {
				memory->free(memory, (URI_CHAR *)oldUri.hostData.ipFuture.first);
			}
		} else if (oldUri.hostText.first != NULL) {
			if ((oldUri.owner == URI_TRUE) && (oldUri.hostText.first != oldUri.hostText.afterLast)) {
				memory->free(memory, (URI_CHAR *)oldUri.hostText.first);
			}
		}

		memory->free(memory, oldUri.hostData.ip4);
		memory->free(memory, oldUri.hostData.ip6);
	}

	return URI_SUCCESS;
}



#endif
