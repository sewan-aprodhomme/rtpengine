#ifndef XT_RTPPROXY_H
#define XT_RTPPROXY_H



#define RTPE_NUM_PAYLOAD_TYPES 32
#define RTPE_MAX_FORWARD_DESTINATIONS 32
#define RTPE_NUM_SSRC_TRACKING 4



struct xt_rtpengine_info {
	unsigned int			id;
};

struct rtpengine_stats {
	uint64_t			packets;
	uint64_t			bytes;
	uint64_t			errors;
	uint64_t			delay_min;
	uint64_t			delay_avg;
	uint64_t			delay_max;
	uint8_t            in_tos;
};
struct rtpengine_rtp_stats {
	uint64_t			packets;
	uint64_t			bytes;
};
struct rtpengine_ssrc_stats {
	struct rtpengine_rtp_stats	basic_stats;
	uint32_t			timestamp;
	uint32_t			ext_seq;
	uint32_t			lost_bits; // sliding bitfield, [0] = ext_seq
	uint32_t			total_lost;
	uint32_t			transit;
	uint32_t			jitter;
};

struct re_address {
	int				family;
	union {
		unsigned char		ipv6[16];
		uint32_t		ipv4;

		unsigned char		u8[16];
		uint16_t		u16[8];
		uint32_t		u32[4];
	}				u;
	uint16_t			port;
};

enum rtpengine_cipher {
	REC_INVALID	= 0,
	REC_NULL,
	REC_AES_CM_128,
	REC_AES_F8,
	REC_AES_CM_192,
	REC_AES_CM_256,
	REC_AEAD_AES_GCM_128,
	REC_AEAD_AES_GCM_256,

	__REC_LAST
};

enum rtpengine_hmac {
	REH_INVALID	= 0,
	REH_NULL,
	REH_HMAC_SHA1,

	__REH_LAST
};


struct rtpengine_srtp {
	enum rtpengine_cipher		cipher;
	enum rtpengine_hmac		hmac;
	unsigned char			master_key[32];
	unsigned int			master_key_len;
	unsigned char			master_salt[14];
	unsigned int			master_salt_len;
	unsigned int			session_key_len;
	unsigned int			session_salt_len;
	unsigned char			mki[256]; /* XXX uses too much memory? */
	uint64_t			last_rtp_index[RTPE_NUM_SSRC_TRACKING];
	uint64_t			last_rtcp_index[RTPE_NUM_SSRC_TRACKING];
	unsigned int			rtp_auth_tag_len; /* in bytes */
	unsigned int			rtcp_auth_tag_len; /* in bytes */
	unsigned int			mki_len;
};


enum rtpengine_src_mismatch {
	MSM_IGNORE	= 0,	/* process packet as normal */
	MSM_DROP,		/* drop packet */
	MSM_PROPAGATE,		/* propagate to userspace daemon */
};

struct rtpengine_payload_type {
	unsigned char pt_num;
	unsigned char replace_pattern_len;
	uint32_t clock_rate;
	char replace_pattern[16];
};

struct rtpengine_target_info {
	struct re_address		local;
	struct re_address		expected_src; /* for incoming packets */
	enum rtpengine_src_mismatch	src_mismatch;
	unsigned int			num_destinations;
	unsigned int			intercept_stream_idx;

	struct rtpengine_srtp		decrypt;
	uint32_t			ssrc[RTPE_NUM_SSRC_TRACKING]; // Expose the SSRC to userspace when we resync.

	struct rtpengine_payload_type	payload_types[RTPE_NUM_PAYLOAD_TYPES]; /* must be sorted */
	unsigned int			num_payload_types;

	unsigned int			rtcp_mux:1,
					dtls:1,
					stun:1,
					rtp:1,
					rtp_only:1,
					rtcp:1,
					rtcp_fb_fw:1,
					do_intercept:1,
					transcoding:1, // SSRC subst and RTP PT filtering
					non_forwarding:1, // empty src/dst addr
					blackhole:1,
					rtp_stats:1; // requires SSRC and clock_rates to be set
};

struct rtpengine_output_info {
	struct re_address		src_addr; /* for outgoing packets */
	struct re_address		dst_addr;

	struct rtpengine_srtp		encrypt;
	uint32_t			ssrc_out[RTPE_NUM_SSRC_TRACKING]; // Rewrite SSRC

	unsigned char			tos;
};

struct rtpengine_destination_info {
	struct re_address		local;
	unsigned int			num;
	struct rtpengine_output_info	output;
};

struct rtpengine_call_info {
	unsigned int			call_idx;
	char				call_id[256];
};

struct rtpengine_stream_info {
	unsigned int			call_idx;
	unsigned int			stream_idx;
	unsigned int			max_packets;
	char				stream_name[256];
};

struct rtpengine_packet_info {
	unsigned int			call_idx;
	unsigned int			stream_idx;
};

struct rtpengine_stats_info {
	struct re_address		local;		// input
	uint32_t			ssrc[RTPE_NUM_SSRC_TRACKING];		// output
	struct rtpengine_ssrc_stats	ssrc_stats[RTPE_NUM_SSRC_TRACKING];	// output
};

struct rtpengine_noop_info {
	size_t				noop_size;
	size_t				target_size;
	size_t				destination_size;
	int				last_cmd;
};

struct rtpengine_send_packet_info {
	struct re_address		local;
	unsigned int			destination_idx;
	struct re_address		src_addr;
	struct re_address		dst_addr;
};

struct rtpengine_message_cmd {
	enum {
		/* noop_info: */
		REMG_NOOP = 1,

		/* target_info: */
		REMG_ADD_TARGET,
		REMG_DEL_TARGET,

		/* destination_info: */
		REMG_ADD_DESTINATION,

		/* call_info: */
		REMG_ADD_CALL,
		REMG_DEL_CALL,

		/* stream_info: */
		REMG_ADD_STREAM,
		REMG_DEL_STREAM,

		/* packet_info: */
		REMG_PACKET,

		/* stats_info: */
		REMG_GET_STATS,
		REMG_GET_RESET_STATS,

		/* send_packet_info: */
		REMG_SEND_RTCP,

		__REMG_LAST
	}				cmd;

	char rest[];
};

struct rtpengine_message_noop {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_noop_info	noop;
};
struct rtpengine_message_target {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_target_info	target;
};
struct rtpengine_message_destination {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_destination_info destination;
};
struct rtpengine_message_call {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_call_info	call;
};
struct rtpengine_message_stream {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_stream_info	stream;
};
struct rtpengine_message_packet {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_packet_info	packet;
	unsigned char			data[];
};
struct rtpengine_message_stats {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_stats_info	stats;
};
struct rtpengine_message_send_packet {
	struct rtpengine_message_cmd	cmd;
	struct rtpengine_send_packet_info send_packet;
	unsigned char			data[];
};

struct rtpengine_list_entry {
	struct rtpengine_target_info	target;
	struct rtpengine_stats		stats;
	struct rtpengine_rtp_stats	rtp_stats[RTPE_NUM_PAYLOAD_TYPES];
	struct rtpengine_output_info	outputs[RTPE_MAX_FORWARD_DESTINATIONS];
};


#endif
