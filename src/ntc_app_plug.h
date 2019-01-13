#ifndef	__NTC_APP_PLUG_H__
#define	__NTC_APP_PLUG_H__

#include <MESA/MESA_htable.h>
#include <soq/soq_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define	MAX_MAAT_RESULT	8

#define	RAW_FEEDBACK_UNKNOW	0
#define	RAW_FEEDBACK_START	1
#define	RAW_FEEDBACK_SSL	2
#define	RAW_FEEDBACK_STOP	3

#define	IS_FEEDBACK_GRE		1
#define	IS_FEEDBACK_SSL		2
#define	IS_FEEDBACK_SSH_VPN	4
#define	IS_FEEDBACK_STATIS		8

#define NTC_STATIS_COLUMN_NUM 	5
#define NTC_STATIS_C2S_PKTS	 	0
#define NTC_STATIS_C2S_BYTES	1
#define NTC_STATIS_S2C_PKTS	 	2
#define NTC_STATIS_S2C_BYTES	3
#define NTC_STATIS_LINKS		4


typedef struct _dpkt_lable_t
{
	unsigned char trans_proto;
	unsigned char v6;
	unsigned short _pad0;
//	uint16_t dpkt_app_ser_type;
//	uint16_t dpkt_proto_ser_type;
	unsigned int dpkt_proto_type;
	unsigned int dpkt_app_type;
	unsigned int dpkt_op_type;
	unsigned int dpkt_browser_type;
	unsigned int dpkt_web_type;
	unsigned int dpkt_behavior_type;
 }dpkt_lable_t;

#define	MAX_VALUE_TYPE	2
#define	NEW_VALUE	0
#define	OLD_VALUE	1
typedef struct _comm_context_t
{
	int	fs2_id;
	soq_protocol_t ddp_proto;
	unsigned int is_feedback;
	unsigned int links[MAX_VALUE_TYPE];
	unsigned int c2s_pkts[MAX_VALUE_TYPE];
	unsigned int s2c_pkts[MAX_VALUE_TYPE];
	unsigned int c2s_bytes[MAX_VALUE_TYPE];
	unsigned int s2c_bytes[MAX_VALUE_TYPE];
	void *ddp_handle;
 }comm_context_t;

#define	MAX_PATHFILE_LENGTH	256
	

typedef struct _ntc_app_plug
{
	int telegraf_port;
	int log_level;
	int dpkt_cons_label_id;
	int ssl_cons_label_id;
	int ssl_prod_label_id;
	int table_id;
	int stat_cycle;
	int tcp_pkt_interval;
	int udp_pkt_interval;
	int is_feedback;
	int statis_line_num;
	int statis_column_id[NTC_STATIS_COLUMN_NUM];
	void *log_handle;
	char telegaf_ip[16];
	screen_stat_handle_t fs2_handle;
	char log_path[MAX_PATHFILE_LENGTH];
	MESA_htable_handle *lhash_handle;
	MESA_htable_handle ghash_handle;
}g_ntc_app_plug_t;

int NTC_APP_PLUG_INIT();
void NTC_APP_PLUG_DESTORY();
char NTC_APP_PLUG_TCP_ENTRY(const struct streaminfo *a_tcp,  void **pme, int thread_seq,const void *rawpkt);
char NTC_APP_PLUG_UDP_ENTRY(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *rawpkt);
char NTC_GRE_IP_ENTRY(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const void *rawpkt);
char NTC_SSL_LABEL_PLUG_ENTRY(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet);


#ifdef __cplusplus
}
#endif


#endif
