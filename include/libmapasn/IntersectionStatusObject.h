/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "J2735MAPMESSAGE"
 * 	found in "module.asn1"
 * 	`asn1c -S/skeletons`
 */

#ifndef	_IntersectionStatusObject_H_
#define	_IntersectionStatusObject_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IntersectionStatusObject */
typedef OCTET_STRING_t	 IntersectionStatusObject_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntersectionStatusObject;
asn_struct_free_f IntersectionStatusObject_free;
asn_struct_print_f IntersectionStatusObject_print;
asn_constr_check_f IntersectionStatusObject_constraint;
ber_type_decoder_f IntersectionStatusObject_decode_ber;
der_type_encoder_f IntersectionStatusObject_encode_der;
xer_type_decoder_f IntersectionStatusObject_decode_xer;
xer_type_encoder_f IntersectionStatusObject_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _IntersectionStatusObject_H_ */
