/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "J2735MAPMESSAGE"
 * 	found in "module.asn1"
 * 	`asn1c -S/skeletons`
 */

#ifndef	_ApproachObject_H_
#define	_ApproachObject_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LaneWidth.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Position3D;
struct Approach;

/* ApproachObject */
typedef struct ApproachObject {
	struct Position3D	*refPoint	/* OPTIONAL */;
	LaneWidth_t	*laneWidth	/* OPTIONAL */;
	struct Approach	*approach	/* OPTIONAL */;
	struct Approach	*egress	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ApproachObject_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ApproachObject;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Position3D.h"
#include "Approach.h"

#endif	/* _ApproachObject_H_ */