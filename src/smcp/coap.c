/*	@file coap.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert_macros.h"
#include "coap.h"
#include <stdlib.h>
#include "ctype.h"

#include "smcp-helpers.h"

uint8_t*
coap_decode_option(const uint8_t* buffer, coap_option_key_t* key, const uint8_t** value, size_t* lenP) {
	uint16_t len;

again:

	len = (*buffer & 0x0F);

	if((*buffer >> 4) == 0xF) {
		// Special option.
		switch(len) {
			case 1:
				// Delta = 15
				*key += 15;
				buffer += 1;
				goto again;
				break;
			case 2:
				*key += 16+(buffer[1]*8);
				buffer += 2;
				goto again;
				break;
			case 3:
				*key += 2064+(buffer[1]*8*256)+(buffer[2]*8);
				buffer += 3;
				goto again;
				break;
			default:
				// Unknown special options marker.
				assert_printf("Unknown special option, \"%d\"",(*buffer >> 4));
			case 0:
				// End of options marker.
				if(key)*key = COAP_HEADER_INVALID;
				if(value)*value = NULL;
				if(lenP)*lenP = 0;
				return NULL;
				break;
		}
	}

	if(key)
		*key += (*buffer >> 4);

	buffer++;

	if(len == 0xF)
		len += *buffer++;

	if(len == 270)
		len += *buffer++;

	if(len == 525)
		len += *buffer++;

	if(len == 780)
		len += *buffer++;


	if(lenP) *lenP = len;
	if(value) *value = buffer;

	return buffer + len;
}

uint8_t*
coap_encode_option(
	uint8_t* buffer,
	coap_option_key_t prev_key,
	coap_option_key_t key,
	const uint8_t* value,
	size_t len
) {
	uint16_t option_delta = key - prev_key;

	if(option_delta>14) {
		if(option_delta < 15+15) {
			*buffer++ = 0xF1;
			option_delta -= 15;
		} else if(option_delta<2064) {
			*buffer++ = 0xF2;
			*buffer++ = (option_delta/8)-2;
			option_delta -= (option_delta/8)*8;
		} else {
			uint16_t d = (option_delta/8)-258;
			*buffer++ = 0xF3;
			*buffer++ = (d>>8);
			*buffer++ = (d&0xFF);
			option_delta -= (option_delta/8)*8;
		}
	}

	check(len <= (COAP_MAX_OPTION_VALUE_SIZE));

	if(len > COAP_MAX_OPTION_VALUE_SIZE)
		len = COAP_MAX_OPTION_VALUE_SIZE;

	if(len<16) {
		*buffer++ = (option_delta << 4) | len;
	} else {
		*buffer++ = (option_delta << 4) | 0xF;
		if(len>=780) {
			*buffer++ = 0xFF;
			*buffer++ = 0xFF;
			*buffer++ = 0xFF;
			*buffer++ = len-780;
		} else if(len>=525) {
			*buffer++ = 0xFF;
			*buffer++ = 0xFF;
			*buffer++ = len-525;
		} else if(len>=270) {
			*buffer++ = 0xFF;
			*buffer++ = len-270;
		} else {
			*buffer++ = len-15;
			*buffer++ = len;
		}
	}

	memcpy(buffer, value, len);
	buffer += len;

	return buffer;
}

extern size_t coap_insert_option(
	uint8_t* start_of_options,
	uint8_t* end_of_options,
	coap_option_key_t key,
	const uint8_t* value,
	size_t len
) {
	size_t size_diff = 0;
	uint8_t* iter = start_of_options;
	uint8_t* insertion_point = start_of_options;
	coap_option_key_t prev_key = 0;
	coap_option_key_t iter_key = 0;

	// Find out insertion point.
	if(start_of_options==end_of_options) {
		iter = NULL;
	} else {
		do {
			iter = coap_decode_option(iter, &iter_key, NULL, NULL);
			if(iter_key<=key) {
				insertion_point = iter;
				prev_key = iter_key;
			}
			if(iter_key>key)
				break;
		} while(iter && iter<end_of_options);
	}

	if(iter && (iter_key>key || iter<end_of_options)) {
		size_diff += len + 1;

		// Compensate for jump option before insert
		if(key-prev_key>2064) {
			size_diff+=3;
		} else if(key-prev_key>15) {
			size_diff+=2;
		} else if(key-prev_key==15) {
			size_diff+=1;
		}

		// Compensate for jump option after insert
		if((insertion_point[0]&0xF0) == 0xF0) {
			size_diff -= (insertion_point[0]&0xF);
		}
		if(iter_key-key>2064) {
			size_diff+=3;
		} else if(iter_key-key>15) {
			size_diff+=2;
		} else if(iter_key-key==15) {
			size_diff+=1;
		}

		// Move higher options
		if(size_diff)
			memmove(insertion_point+size_diff,insertion_point,end_of_options-insertion_point);

		// encode new option
		iter = coap_encode_option(insertion_point, prev_key, key, value, len);

		// TODO: There may be a bug here when inserting values that cause a jump option to be removed!

		// Update fisrt option after
		{
			coap_decode_option(insertion_point+size_diff, &prev_key, &value, &len);
			coap_encode_option(iter, key, prev_key, value, len);
		}

	} else {
		// encode new option
		size_diff = coap_encode_option(end_of_options, prev_key, key, value, len) - end_of_options;
	}

bail:
	return size_diff;
}

uint16_t coap_to_http_code(uint8_t x) { return COAP_TO_HTTP_CODE(x); }

uint8_t http_to_coap_code(uint16_t x) { return HTTP_TO_COAP_CODE(x); }

bool
coap_option_strequal(const char* optionptr,const char* cstr) {
	// TODO: This looks easily optimizable.
	const char* value;
	size_t value_len;
	size_t i;
	if(!coap_decode_option((const uint8_t*)optionptr, NULL, (const uint8_t**)&value, &value_len))
		return false;

	for(i=0;i<value_len;i++) {
		if(!cstr[i] || (value[i]!=cstr[i]))
			return false;
	}
	return cstr[i]==0;
}

const char*
coap_content_type_to_cstr(coap_content_type_t content_type) {
	const char* content_type_string = NULL;

//	if((content_type>255) || (content_type<0))
//		content_type = COAP_CONTENT_TYPE_UNKNOWN;

	switch(content_type) {
	case COAP_CONTENT_TYPE_UNKNOWN: content_type_string = "unknown"; break;

	case COAP_CONTENT_TYPE_TEXT_PLAIN: content_type_string = "text/plain;charset=utf-8";
		break;
	case COAP_CONTENT_TYPE_TEXT_XML: content_type_string = "text/xml";
		break;
	case COAP_CONTENT_TYPE_TEXT_CSV: content_type_string = "text/csv";
		break;
	case COAP_CONTENT_TYPE_TEXT_HTML: content_type_string = "text/html";
		break;

	case COAP_CONTENT_TYPE_IMAGE_GIF: content_type_string = "image/gif";
		break;
	case COAP_CONTENT_TYPE_IMAGE_JPEG: content_type_string = "image/jpeg";
		break;
	case COAP_CONTENT_TYPE_IMAGE_PNG: content_type_string = "image/png";
		break;
	case COAP_CONTENT_TYPE_IMAGE_TIFF: content_type_string = "image/tiff";
		break;

	case COAP_CONTENT_TYPE_AUDIO_RAW: content_type_string = "audio/raw";
		break;
	case COAP_CONTENT_TYPE_VIDEO_RAW: content_type_string = "video/raw";
		break;

	case COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT: content_type_string =
		    "application/link-format"; break;
	case COAP_CONTENT_TYPE_APPLICATION_XML: content_type_string =
		    "application/xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM: content_type_string =
		    "application/octet-stream"; break;
	case COAP_CONTENT_TYPE_APPLICATION_RDF_XML: content_type_string =
		    "application/rdf+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_SOAP_XML: content_type_string =
		    "application/soap+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_ATOM_XML: content_type_string =
		    "application/atom+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_XMPP_XML: content_type_string =
		    "application/xmpp+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_EXI: content_type_string =
		    "application/exi"; break;

	case COAP_CONTENT_TYPE_APPLICATION_X_BXML: content_type_string =
		    "application/x-bxml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_FASTINFOSET: content_type_string =
		    "application/fastinfoset"; break;
	case COAP_CONTENT_TYPE_APPLICATION_JSON: content_type_string =
		    "application/json"; break;

	case SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
		content_type_string = "application/x-www-form-urlencoded"; break;

	default: break;
	}
	if(!content_type_string) {
#if !defined(__SDCC)
		// TODO: Make thread safe!
		static char ret[40];
		if(content_type < 20)
			snprintf(ret,
				sizeof(ret),
				"text/x-coap-%u;charset=utf-8",
				    (unsigned char)content_type);
		else if(content_type < 40)
			snprintf(ret,
				sizeof(ret),
				"image/x-coap-%u",
				    (unsigned char)content_type);
		else if(content_type < 60)
			snprintf(ret, sizeof(ret), "application/x-coap-%u",
				    (unsigned char)content_type);
		else if(content_type < 201)
			snprintf(ret, sizeof(ret), "application/x-coap-%u",
				    (unsigned char)content_type);
		else
			// Experimental
			snprintf(ret, sizeof(ret), "application/x-coap-%u",
				    (unsigned char)content_type);
		content_type_string = ret;
#else
		content_type_string = "unknown";
#endif
	}
	return content_type_string;
}

coap_content_type_t
coap_content_type_from_cstr(const char* x) {
	if(!x)
		return COAP_CONTENT_TYPE_UNKNOWN;

	if(strhasprefix_const(x, "application/x-coap-"))
		x += sizeof("application/x-coap-") - 1;
	else if(strhasprefix_const(x, "text/x-coap-"))
		x += sizeof("text/x-coap-") - 1;
	else if(strhasprefix_const(x, "image/x-coap-"))
		x += sizeof("image/x-coap-") - 1;

	if(isdigit(x[0]))
		return atoi(x);

	if(strhasprefix_const(x, "text/plain"))
		return COAP_CONTENT_TYPE_TEXT_PLAIN;
	if(strhasprefix_const(x, "text/html"))
		return COAP_CONTENT_TYPE_TEXT_HTML;
	if(strhasprefix_const(x, "text/xml"))
		return COAP_CONTENT_TYPE_APPLICATION_XML;
	if(strhasprefix_const(x, "text/"))
		return COAP_CONTENT_TYPE_TEXT_PLAIN;
	if(strhasprefix_const(x, "application/x-www-form-urlencoded"))
		return SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
	if(strhasprefix_const(x, "application/link-format"))
		return COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;
	if(strhasprefix_const(x, "application/octet-stream"))
		return COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM;

	// TODO: Add the others!

	return COAP_CONTENT_TYPE_UNKNOWN;
}

bool
coap_option_value_is_string(coap_option_key_t key) {
	switch(key) {
		case COAP_HEADER_PROXY_URI:
		case SMCP_HEADER_CSEQ:
		case COAP_HEADER_ETAG:
		case COAP_HEADER_URI_HOST:
		case COAP_HEADER_LOCATION_PATH:
		case COAP_HEADER_LOCATION_QUERY:
		case COAP_HEADER_URI_PATH:
			return true;
			break;
		default:
			break;
	}
	return false;
}

const char*
coap_option_key_to_cstr(
	coap_option_key_t key, bool for_response
) {
	const char* ret = NULL;

	if(for_response) switch(key) {
#ifdef USE_DRAFT_BORMANN_CORE_COAP_BLOCK_01_ALT
		case COAP_HEADER_MESSAGE_SIZE: ret = "Message-size"; break;
		case COAP_HEADER_CONTINUATION_REQUEST: ret =
			    "Continuation-request"; break;
#endif
		default: break;
		}
	if(!ret) switch(key) {
		case COAP_HEADER_CONTENT_TYPE: ret = "Content-type"; break;
		case COAP_HEADER_MAX_AGE: ret = "Max-age"; break;
		case COAP_HEADER_ETAG: ret = "Etag"; break;
		case COAP_HEADER_PROXY_URI: ret = "Proxy-uri"; break;
		case COAP_HEADER_URI_HOST: ret = "URI-host"; break;
		case COAP_HEADER_URI_PORT: ret = "URI-port"; break;
		case COAP_HEADER_URI_PATH: ret = "URI-path"; break;
		case COAP_HEADER_URI_QUERY: ret = "URI-query"; break;
		case COAP_HEADER_LOCATION_PATH: ret = "Location-path"; break;
		case COAP_HEADER_LOCATION_QUERY: ret = "Location-query"; break;

		case COAP_HEADER_ACCEPT: ret = "Accept"; break;
		case COAP_HEADER_OBSERVE: ret = "Observe"; break;
		case COAP_HEADER_TOKEN: ret = "Token"; break;

		case COAP_HEADER_BLOCK1: ret = "Block1"; break;
		case COAP_HEADER_BLOCK2: ret = "Block2"; break;

//		case COAP_HEADER_09_BLOCK1: ret = "Draft-9-Block1"; break;
//		case COAP_HEADER_09_BLOCK2: ret = "Draft-9-Block2"; break;

/* -- EXPERIMENTAL AFTER THIS POINT -- */

//#if !USE_DRAFT_BORMANN_CORE_COAP_BLOCK_01_ALT
//		case COAP_HEADER_MESSAGE_SIZE: ret = "Message-size"; break;
//		case COAP_HEADER_NEXT: ret = "Next"; break;
//#endif



		case COAP_HEADER_CASCADE_COUNT: ret = "Cascade-count"; break;
//		case COAP_HEADER_RANGE: ret = "Range"; break;
//		case COAP_HEADER_BLOCK: ret = "Block"; break;
//		case COAP_HEADER_ALLOW: ret = "Allow"; break;

//		case COAP_HEADER_SIZE_REQUEST: ret = "Size-request"; break;
//		case COAP_HEADER_CONTINUATION_RESPONSE: ret = "Continuation-response"; break;

		case SMCP_HEADER_CSEQ: ret = "Cseq"; break;
		case SMCP_HEADER_ORIGIN: ret = "Origin"; break;

		default:
		{
			static char x[30];
			if(key % 14) {
				if(key & 1)
					sprintf(x, "X-Critical-CoAP-%u", key);
				else
					sprintf(x, "X-Elective-CoAP-%u", key);
			} else {
				sprintf(x, "Ignore-%u", key);
			}
			ret = x;
		}
		break;
		}
	return ret;
}

#if !defined(__SDCC)
coap_option_key_t
coap_option_key_from_cstr(const char* key) {
	if(strcasecmp(key, "Content-type") == 0)
		return COAP_HEADER_CONTENT_TYPE;
	else if(strcasecmp(key, "Max-age") == 0)
		return COAP_HEADER_MAX_AGE;
	else if(strcasecmp(key, "Etag") == 0)
		return COAP_HEADER_ETAG;
	else if(strcasecmp(key, "URI-host") == 0)
		return COAP_HEADER_URI_HOST;
	else if(strcasecmp(key, "Proxy-uri") == 0)
		return COAP_HEADER_PROXY_URI;
	else if(strcasecmp(key, "URI-port") == 0)
		return COAP_HEADER_URI_PORT;
	else if(strcasecmp(key, "Location-path") == 0)
		return COAP_HEADER_LOCATION_PATH;
	else if(strcasecmp(key, "Location-query") == 0)
		return COAP_HEADER_LOCATION_QUERY;
	else if(strcasecmp(key, "URI-path") == 0)
		return COAP_HEADER_URI_PATH;
	else if(strcasecmp(key, "Accept") == 0)
		return COAP_HEADER_ACCEPT;

	else if(strcasecmp(key, "Cseq") == 0)
		return SMCP_HEADER_CSEQ;
//	else if(strcasecmp(key, "Range") == 0)
//		return COAP_HEADER_RANGE;

	else if(strcasecmp(key, "Block1") == 0)
		return COAP_HEADER_BLOCK1;
	else if(strcasecmp(key, "Block2") == 0)
		return COAP_HEADER_BLOCK2;

//	else if(strcasecmp(key, "Draft-9-Block1") == 0)
//		return COAP_HEADER_09_BLOCK1;
//	else if(strcasecmp(key, "Draft-9-Block2") == 0)
//		return COAP_HEADER_09_BLOCK2;
	else if(strcasecmp(key, "Origin") == 0)
		return SMCP_HEADER_ORIGIN;

//	else if(strcasecmp(key, "Next") == 0)
//		return COAP_HEADER_NEXT;
//	else if(strcasecmp(key, "Allow") == 0)
//		return COAP_HEADER_ALLOW;


	return 0;
}
#endif

const char*
http_code_to_cstr(int x) {
	switch(x) {
	case COAP_CODE_EMPTY: return "EMPTY"; break;
	case COAP_METHOD_GET: return "GET"; break;
	case COAP_METHOD_POST: return "POST"; break;
	case COAP_METHOD_PUT: return "PUT"; break;
	case COAP_METHOD_DELETE: return "DELETE"; break;

	case HTTP_RESULT_CODE_CONTINUE: return "CONTINUE"; break;
	case HTTP_RESULT_CODE_OK: return "OK"; break;
	case HTTP_RESULT_CODE_CONTENT: return "CONTENT"; break;
	case HTTP_RESULT_CODE_VALID: return "VALID"; break;
	case HTTP_RESULT_CODE_CREATED: return "CREATED"; break;
	case HTTP_RESULT_CODE_CHANGED: return "CHANGED"; break;
	case HTTP_RESULT_CODE_DELETED: return "DELETED"; break;
	case HTTP_RESULT_CODE_PARTIAL_CONTENT: return "PARTIAL_CONTENT"; break;
	case HTTP_RESULT_CODE_BAD_OPTION: return "BAD_OPTION"; break;
	case HTTP_RESULT_CODE_NOT_ACCEPTABLE: return "NOT_ACCEPTABLE"; break;
	case HTTP_RESULT_CODE_NOT_MODIFIED: return "NOT_MODIFIED"; break;
	case HTTP_RESULT_CODE_SEE_OTHER: return "SEE_OTHER"; break;
	case HTTP_RESULT_CODE_TEMPORARY_REDIRECT: return "TEMPORARY_REDIRECT";
		break;

	case HTTP_RESULT_CODE_REQUEST_TIMEOUT: return "REQUEST_TIMEOUT"; break;

	case HTTP_RESULT_CODE_BAD_REQUEST: return "BAD_REQUEST"; break;
	case HTTP_RESULT_CODE_UNAUTHORIZED: return "UNAUTHORIZED"; break;
	case HTTP_RESULT_CODE_FORBIDDEN: return "FORBIDDEN"; break;
	case HTTP_RESULT_CODE_NOT_FOUND: return "NOT_FOUND"; break;
	case HTTP_RESULT_CODE_METHOD_NOT_ALLOWED: return "METHOD_NOT_ALLOWED";
		break;
	case HTTP_RESULT_CODE_CONFLICT: return "CONFLICT"; break;
	case HTTP_RESULT_CODE_GONE: return "GONE"; break;
	case HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE: return
		    "UNSUPPORTED_MEDIA_TYPE"; break;

	case HTTP_RESULT_CODE_INTERNAL_SERVER_ERROR: return
		    "INTERNAL_SERVER_ERROR"; break;
	case HTTP_RESULT_CODE_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED"; break;
	case HTTP_RESULT_CODE_BAD_GATEWAY: return "BAD_GATEWAY"; break;
	case HTTP_RESULT_CODE_SERVICE_UNAVAILABLE: return "UNAVAILABLE"; break;
	case HTTP_RESULT_CODE_GATEWAY_TIMEOUT: return "TIMEOUT"; break;
	case HTTP_RESULT_CODE_PROXYING_NOT_SUPPORTED: return
		    "PROXYING_NOT_SUPPORTED"; break;

//	case HTTP_RESULT_CODE_TOKEN_REQUIRED: return "TOKEN_REQUIRED"; break;
//	case HTTP_RESULT_CODE_URI_AUTHORITY_REQUIRED: return
//		    "URI_AUTHORITY_REQUIRED"; break;
//	case HTTP_RESULT_CODE_UNSUPPORTED_CRITICAL_OPTION: return
//		    "UNSUPPORTED_CRITICAL_OPTION"; break;
	default:  break;
	}
	return "UNKNOWN";
}

const char* coap_code_to_cstr(int x) { return http_code_to_cstr(coap_to_http_code(x)); }

#if !defined(__SDCC)
void
coap_dump_header(
	FILE*			outstream,
	const char*		prefix,
	const struct coap_header_s* header,
	size_t packet_size
) {
	coap_option_key_t key = 0;
	const uint8_t* value;
	size_t value_len;
	int option_count = header->option_count;
	const uint8_t* option_ptr = header->options;

	if(!prefix)
		prefix = "";

	if(header->code >= COAP_RESULT_100) {
		fputs(prefix, outstream);
		fprintf(outstream,
			"CoAP/1.0 %d %s tt=%d tid=%d\n",
			coap_to_http_code(header->code),
			coap_code_to_cstr(header->code),
			header->tt,header->tid
		);
	} else {
		fputs(prefix, outstream);
		fprintf(outstream, "%s(%d) /", coap_code_to_cstr(header->code),header->code);

		fprintf(outstream, " CoAP/1.0 tt=%d tid=%d\n",
			header->tt,header->tid
		);
	}

	for(;option_ptr && option_count && (option_count!=15 || option_ptr[0]!=0xF0);) {
		option_ptr = coap_decode_option(option_ptr, &key, &value, &value_len);
		if(option_count!=15) {
			--option_count;
			if(!option_ptr) {
				fputs(prefix, outstream);
				fprintf(outstream,"OPTIONS ARE CORRUPTED.");
				break;
			}
		} else {
			if(!option_ptr) {
				break;
			}
		}
//		if(!(key%14))
//			continue;
		fputs(prefix, outstream);
		fprintf(outstream, "%s: ",
			coap_option_key_to_cstr(key, header->code >= COAP_RESULT_100));
		switch(key) {
		case COAP_HEADER_CONTENT_TYPE:
			fprintf(outstream, "%s",
				coap_content_type_to_cstr((unsigned char)value[0]));
			break;
		case COAP_HEADER_CASCADE_COUNT:
		case COAP_HEADER_MAX_AGE:
		case COAP_HEADER_URI_PORT:
		{
			unsigned long age = 0;
			uint8_t i;
			for(i = 0; i < value_len; i++)
				age = (age << 8) + value[i];
			fprintf(outstream, "%lu", age);
		}
		break;
		case COAP_HEADER_ACCEPT:
		{
			size_t i;
			for(i = 0; i < value_len; i++) {
				if(i)
					fputc(',', outstream);
				fprintf(outstream, "%s",
					    coap_content_type_to_cstr((uint8_t)value[i]));
			}
		}
		break;
		case COAP_HEADER_BLOCK1:
		case COAP_HEADER_BLOCK2:
//		case COAP_HEADER_09_BLOCK1:
//		case COAP_HEADER_09_BLOCK2:
		{
			uint32_t block;
			if(value_len==1)
				block = (value[0]>>4);
			else if(value_len==2)
				block = (value[0]<<4)+(value[1]>>4);
			else if(value_len==3)
				block = (value[1]<<12)+(value[1]<<4)+(value[2]>>4);
			fprintf(outstream,
				"%d/%d/%d",
				block,
				(value[value_len-1]&(1<<3))!=0,
				1<<((value[value_len-1]&(0x7))+4)
			);
		}
		break;

		case COAP_HEADER_URI_PATH:
		case COAP_HEADER_URI_HOST:
		case COAP_HEADER_URI_QUERY:
		case COAP_HEADER_PROXY_URI:
		case COAP_HEADER_LOCATION_PATH:
		case COAP_HEADER_LOCATION_QUERY:

		case SMCP_HEADER_ORIGIN:
		case SMCP_HEADER_CSEQ:

			fprintf(outstream, "\"");
			if(value_len > 270)
				fprintf(outstream, "%s",value);
			else
				fwrite(value, value_len, 1, outstream);
			fprintf(outstream, "\"");
			break;

		default:
		{
			size_t i;
			if(value_len > 270) {
				fprintf(outstream, "***VALUE LENGTH OVERFLOW***");
			} else
			for(i = 0; i < value_len; i++) {
				fprintf(outstream, "%02X ", (uint8_t)value[i]);
			}
		}
		break;
		}
		fputc('\n', outstream);
	}

	fputs(prefix, outstream);
	fputc('\n', outstream);
}
#endif
