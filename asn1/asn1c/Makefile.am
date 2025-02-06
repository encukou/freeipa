libasn1c_la_SOURCES =		\
	asn_application.h	\
	asn_bit_data.c		\
	asn_bit_data.h		\
	asn_codecs.h		\
	asn_codecs_prim.c	\
	asn_codecs_prim.h	\
	asn_internal.c		\
	asn_internal.h		\
	asn_random_fill.c	\
	asn_random_fill.h	\
	asn_SEQUENCE_OF.c	\
	asn_SEQUENCE_OF.h	\
	asn_SET_OF.c		\
	asn_SET_OF.h		\
	asn_system.h		\
	ber_decoder.c		\
	ber_decoder.h		\
	ber_tlv_length.c	\
	ber_tlv_length.h	\
	ber_tlv_tag.c		\
	ber_tlv_tag.h		\
	BIT_STRING.c		\
	BIT_STRING.h		\
	BIT_STRING_oer.c	\
	constraints.c		\
	constraints.h		\
	constr_CHOICE.c		\
	constr_CHOICE.h		\
	constr_CHOICE_oer.c	\
	constr_SEQUENCE.c	\
	constr_SEQUENCE.h	\
	constr_SEQUENCE_oer.c	\
	constr_SEQUENCE_OF.c	\
	constr_SEQUENCE_OF.h	\
	constr_SET_OF.c		\
	constr_SET_OF.h		\
	constr_SET_OF_oer.c	\
	constr_TYPE.c		\
	constr_TYPE.h		\
	der_encoder.c		\
	der_encoder.h		\
	GetKeytabControl.c	\
	GetKeytabControl.h	\
	GKCurrentKeys.c		\
	GKCurrentKeys.h		\
	GKNewKeys.c		\
	GKNewKeys.h		\
	GKReply.c		\
	GKReply.h		\
	Int32.c			\
	Int32.h			\
	INTEGER.c		\
	INTEGER.h		\
	INTEGER_oer.c		\
	KrbKey.c		\
	KrbKey.h		\
	NativeEnumerated.c	\
	NativeEnumerated.h	\
	NativeEnumerated_oer.c	\
	NativeInteger.c		\
	NativeInteger.h		\
	NativeInteger_oer.c	\
	OCTET_STRING.c		\
	OCTET_STRING.h		\
	OCTET_STRING_oer.c	\
	oer_decoder.c		\
	oer_decoder.h		\
	oer_encoder.c		\
	oer_encoder.h		\
	oer_support.c		\
	oer_support.h		\
	OPEN_TYPE.c		\
	OPEN_TYPE.h		\
	OPEN_TYPE_oer.c		\
	per_decoder.c		\
	per_decoder.h		\
	per_encoder.c		\
	per_encoder.h		\
	per_opentype.c		\
	per_opentype.h		\
	per_support.c		\
	per_support.h		\
	TypeValuePair.c		\
	TypeValuePair.h		\
	xer_decoder.c		\
	xer_decoder.h		\
	xer_encoder.c		\
	xer_encoder.h		\
	xer_support.c		\
	xer_support.h

EXTRA_DIST = ipa.asn1

AM_CPPFLAGS = -I$(top_srcdir)/util

noinst_LTLIBRARIES=libasn1c.la

regenerate:
	asn1c -fskeletons-copy -fnative-types ipa.asn1
	$(SED) -i s/_BSD_SOURCE/_DEFAULT_SOURCE/g asn_system.h
	rm -f converter-sample.c Makefile.am.sample
