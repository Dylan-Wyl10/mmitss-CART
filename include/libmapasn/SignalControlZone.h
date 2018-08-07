/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "J2735MAPMESSAGE"
 * 	found in "module.asn1"
 * 	`asn1c -S/skeletons`
 */

#ifndef	_SignalControlZone_H_
#define	_SignalControlZone_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DescriptiveName.h"
#include "SignalReqScheme.h"
#include "LaneNumber.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include "LaneWidth.h"
#include "NodeList.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum data_PR {
	data_PR_NOTHING,	/* No components present */
	data_PR_laneSet,
	data_PR_zones
} data_PR;

/* SignalControlZone */
typedef struct SignalControlZone {
	DescriptiveName_t	*name	/* OPTIONAL */;
	SignalReqScheme_t	 pValue;
	struct data {
		data_PR present;
		union SignalControlZone__data_u {
			struct laneSet {
				A_SEQUENCE_OF(LaneNumber_t) list;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} laneSet;
			struct zones {
				A_SEQUENCE_OF(struct Member {
					struct enclosed {
						A_SEQUENCE_OF(LaneNumber_t) list;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *enclosed;
					LaneWidth_t	*laneWidth	/* OPTIONAL */;
					NodeList_t	 nodeList;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} ) list;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} zones;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} data;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SignalControlZone_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SignalControlZone;

#ifdef __cplusplus
}
#endif

#endif	/* _SignalControlZone_H_ */
