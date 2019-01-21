#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>

#include <MESA/stream.h>
#include <MESA/ssl.h>
#include <MESA/field_stat2.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>


#include "ntc_app_plug.h"
#include <soq/ddp.h>
#include <soq/soq_types.h>
#include <soq/t1_public.h>
#include <soq/soq_sendlog.h>

const char *app_profile = "./t1conf/main.conf";
g_ntc_app_plug_t g_ntc_app_plug;

int NTC_APP_PLUG_VERSION_20190115=20190115;

const char *ntc_statis_column[NTC_STATIS_COLUMN_NUM] = {"C2S_PKTS", "C2S_BYTES", "S2C_PKTS", "S2C_BYTES", "LINKS"};

void free_buf(void *buf)
{
	free(buf);	
	buf = NULL;
}


long cb_fs2_id(void *data, const uchar *key, uint size, void *user_arg)
{
	int fs2_id = -1;
	int *tmp_fs2_id=NULL;
	
	if(user_arg == NULL)
	{
		if(data == NULL)
		{
			return -1;
		}

		fs2_id= *(int *)data;
	}
	else
	{
		if(data == NULL)
		{
			tmp_fs2_id = (int *)calloc(1, sizeof(int));
			*tmp_fs2_id = FS_register(g_ntc_app_plug.fs2_handle, FS_STYLE_LINE, FS_CALC_CURRENT, (const char *)key);
			MESA_htable_add(user_arg,key, size, (const void *)tmp_fs2_id);
			return (long)(*(int *)tmp_fs2_id); 
		}

		fs2_id= *(int *)data;
	}

	return (long)fs2_id;
}

int get_fs2_id(char *key, int key_len, int thread_seq)
{
	long cb_ret=-1;
	int *tmp_fs2_id=NULL;
	
	MESA_htable_search_cb(g_ntc_app_plug.lhash_handle[thread_seq], (const uchar *)key,(uint)key_len, cb_fs2_id, NULL, &cb_ret);
	if(cb_ret < 0)
	{
		MESA_htable_search_cb(g_ntc_app_plug.ghash_handle, (const uchar *)key,(uint)key_len, cb_fs2_id, g_ntc_app_plug.ghash_handle, &cb_ret);
		tmp_fs2_id = (int *)calloc(1, sizeof(int));
		*tmp_fs2_id = (int)cb_ret;
		MESA_htable_add(g_ntc_app_plug.lhash_handle[thread_seq], (const uchar *)key,(uint)key_len, (const void *)tmp_fs2_id);
		return 	*tmp_fs2_id;
	}

	return (int)cb_ret;
}

int ntc_loop_append_rawpkt(void * ddp_handle, const void*ip, int iplen)
{
	if(ddp_handle == NULL || ip == NULL || iplen <=0)
		return -1;

	#define ONE_PKT_SIZE 1400 
	static const unsigned char FRAG_PKT_MAC[14] = {0x00,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A, 0x0A,0x0A,0x0A,0x0A,0x0A,0x08,0x00};

	int sendnum = 0;
	int reslen=0,pktlen=0;
	unsigned short sendoffset=0;
	char pbuf[ONE_PKT_SIZE+14+20];	
	memset(pbuf, 0, sizeof(pbuf));	
	//copy fake mac header to pbuf
	memcpy(pbuf, FRAG_PKT_MAC, 14);
	//copy ip_hdr to pbuf
	memcpy(pbuf+14,ip,20);
	//minus ip_hdr_len to set reslen as payload len
	reslen=iplen-20;
	struct ip *piph=(struct ip*)(pbuf+14);
	char *ip_payload = pbuf+14+20;
	do
	{
        	memcpy(ip_payload, (const char *)ip+sendoffset+20, reslen>ONE_PKT_SIZE?ONE_PKT_SIZE:reslen);
		if(reslen>ONE_PKT_SIZE)
		{	
			pktlen=ONE_PKT_SIZE+20;
			piph->ip_off = htons((sendoffset/8) | IP_MF);
		}	
		else
		{	
			pktlen=reslen+20;  
			piph->ip_off = htons((sendoffset/8) & IP_OFFMASK );
		}		
		piph->ip_len = htons(pktlen);
		ddp_append(ddp_handle, DIR_C2S, 0, NULL, (char *)pbuf, pktlen+14, 0);	
		sendnum+=1;
		reslen-=(pktlen-20);
		sendoffset+=(pktlen-20);
	
	}while(reslen > 0);
	return sendnum;	
}

int ntc_feedback_rawpkt(void * ddp_handle, const struct streaminfo *a_stream, const void * ip, int iplen)
{
	int ret =0;
	int eth_rawpkt_len = 0;
	void *p_eth_rawpkt = NULL;

	if(ddp_handle == NULL || a_stream == NULL || ip == NULL || iplen <= 0)
	{
		return -1;
	}
		
	get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_DATA, &p_eth_rawpkt);
	get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_TOT_LEN, &eth_rawpkt_len);
	if(p_eth_rawpkt != NULL && eth_rawpkt_len > 0)
	{
		ddp_append(ddp_handle, DIR_C2S, 0, NULL, (char *)p_eth_rawpkt, eth_rawpkt_len, 0);	//rawpkt cur_dir must be static
		ret = eth_rawpkt_len;
	}
	else
	{
		ntc_loop_append_rawpkt(ddp_handle, ip, iplen);
		ret = iplen;
	}
	return ret;
}


int ntc_feedback_single_rawpkt(const struct streaminfo *a_stream, soq_protocol_t proto)
{
	int eth_rawpkt_len = 0;
	void *ddp_handle = NULL, *p_eth_rawpkt = NULL;
	
	int ret = get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_DATA, &p_eth_rawpkt);
	if(ret == 0)
	{
		ret = get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_TOT_LEN, &eth_rawpkt_len);
		if(p_eth_rawpkt != NULL && ret == 0)
		{
			ddp_handle =  ddp_start(proto,a_stream->threadnum);
			ddp_append(ddp_handle, a_stream->curdir, 0, NULL, (char *)p_eth_rawpkt, eth_rawpkt_len, 0);
			ddp_end(ddp_handle);
			return 0;
		}
		MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "ntc_feedback_rawpkt", "RAWPKT_FEEDBACK error, get eth len error");
		return -1;
	}
	
	MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "ntc_feedback_rawpkt", "RAWPKT_FEEDBACK error, get eth pkt return NULL");

	return -1;
}

int init_app_context(comm_context_t **comm_context, int thread_seq)
{
	comm_context_t *context = (comm_context_t *)dictator_malloc(thread_seq, sizeof(comm_context_t));
	memset(context, 0, sizeof(comm_context_t));
	context->fs2_id = -1;
	context->ddp_handle = NULL;
	*comm_context = context;
	
	return 1;
}

void destroy_app_context(comm_context_t *context, int thread_seq)
{
	if(context->ddp_handle != NULL)
	{
		ddp_end(context->ddp_handle);
		context->ddp_handle = NULL;
	}
	
	dictator_free(thread_seq, context);

	context = NULL;

	return ;
}

int ntc_get_dpkt_label(const struct streaminfo *a_stream, int trans_proto, char *label_buf, int *label_buflen, unsigned int *is_feedback)
{
	int ip = 0;
	dpkt_lable_t dpkt_info_null;
	dpkt_lable_t *dpkt_info = NULL;
	struct vxlan_info vinfo;
	int opt_val_len = sizeof(vinfo);

	dpkt_info = (dpkt_lable_t*)project_req_get_struct(a_stream,g_ntc_app_plug.dpkt_cons_label_id);	
	
	if(dpkt_info == NULL)	
	{		
		memset(&dpkt_info_null, 0, sizeof(dpkt_info_null));
		dpkt_info = &dpkt_info_null;
		if(a_stream->addr.addrtype == ADDR_TYPE_IPV4 || a_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
		{
			dpkt_info->v6 = 4;	/* IPV4 */
		}
		else
		{
			dpkt_info->v6 = 6;	/* IPV6 */
		}
		dpkt_info->trans_proto = trans_proto;
		ip=dpkt_info->v6;
	}	
	else
	{
		(dpkt_info->v6)?ip=6:ip=4;	
	}

	memset(&vinfo, 0, opt_val_len);
	MESA_get_stream_opt(a_stream, MSO_STREAM_VXLAN_INFO, &vinfo, &opt_val_len);
	
	snprintf(label_buf, *label_buflen, "IP=%d;TRANS=%d;PROTO_ID=%u;APP_ID=%u;OS_ID=%u;BS_ID=%u;WEB_ID=%u;BEHAV_ID=%u;DIR=%u;",
	//	dpkt_info->v6,
		ip,
		dpkt_info->trans_proto,
		//dpkt_info->dpkt_service_type,			
		dpkt_info->dpkt_proto_type,	        			
		dpkt_info->dpkt_app_type,	        			
		dpkt_info->dpkt_op_type,	        			
		dpkt_info->dpkt_browser_type,	        			
		dpkt_info->dpkt_web_type,	        			
		dpkt_info->dpkt_behavior_type,
		vinfo.link_dir);

	*label_buflen = strlen(label_buf);	
	*is_feedback = dpkt_info->dpkt_behavior_type;
	
	return 0;
}

int ntc_update_comm_context(const struct streaminfo *pstream, comm_context_t *comm_context, soq_protocol_t trans_proto, int state, int pkt_interval, const void *raw_pkt)
{
	int rawpkt_len=0;
	soq_protocol_t v4ORv6=PROTO_IPv4;
	char label_buf[MAX_PATHFILE_LENGTH];
	int label_buflen = sizeof(label_buf);
	struct ip6_hdr * ip6 = NULL;
	struct ip * ip4 = NULL;
	
	if(raw_pkt != NULL)
	{
		switch(pstream->curdir)
		{
			case	DIR_C2S:
				comm_context->c2s_pkts[NEW_VALUE]++;
				comm_context->c2s_bytes[NEW_VALUE] += pstream->ptcpdetail->datalen;
				break;
			case	DIR_S2C:
				comm_context->s2c_pkts[NEW_VALUE]++;
				comm_context->s2c_bytes[NEW_VALUE] += pstream->ptcpdetail->datalen;
				break;
			default:
				return -1;
		}
	}

	if((comm_context->c2s_pkts[NEW_VALUE]+comm_context->s2c_pkts[NEW_VALUE])%pkt_interval == 0 || state == OP_STATE_CLOSE || state == SESSION_STATE_CLOSE)
	{
		if(comm_context->fs2_id < 0)
		{
			if((g_ntc_app_plug.is_feedback&IS_FEEDBACK_STATIS)==IS_FEEDBACK_STATIS)
			{
				ntc_get_dpkt_label(pstream, (trans_proto==PROTO_TCP ? 6 : 17), label_buf, &label_buflen, &comm_context->is_feedback);

				comm_context->fs2_id = get_fs2_id(label_buf, strlen(label_buf), pstream->threadnum);
				assert(comm_context->fs2_id>=0);
			}
		#if 0
			struct soq_log_t log_msg;
			int scan_ret=0,found_pos=0;
			scan_status_t mid = NULL;
			struct Maat_rule_t result[MAX_MAAT_RESULT];
			memset(result, 0, sizeof(result));
			scan_ret = scan_nesting_proto_addr(g_t1_maat_feather, pstream, trans_proto, &mid, result, MAX_MAAT_RESULT);
			scan_ret += Maat_full_scan_string(g_t1_maat_feather, 
											 g_ntc_app_plug.table_id, CHARSET_GBK,
											 label_buf,
											 label_buflen,
											 result+scan_ret,
											 &found_pos,
											 MAX_MAAT_RESULT-scan_ret,
											 &mid,
											 pstream->threadnum);
			if(scan_ret > 0)
			{
				if(fetch_block_rule(result, scan_ret) != NULL && trans_proto == PROTO_TCP)
				{
					MESA_kill_tcp((struct streaminfo *)pstream, raw_pkt);
				}
				
				memset(&log_msg, 0, sizeof(struct soq_log_t));
				log_msg.result = result;
				log_msg.result_num=scan_ret;
				log_msg.stream=pstream;
				soq_send_log(&log_msg, NULL, 0, pstream->threadnum);
			}
			Maat_clean_status(&mid);
		#endif
		}

		if((g_ntc_app_plug.is_feedback&IS_FEEDBACK_STATIS)==IS_FEEDBACK_STATIS)
		{
			FS_operate(g_ntc_app_plug.fs2_handle, comm_context->fs2_id, g_ntc_app_plug.statis_column_id[NTC_STATIS_C2S_PKTS], FS_OP_ADD, comm_context->c2s_pkts[NEW_VALUE]-comm_context->c2s_pkts[OLD_VALUE]);
			FS_operate(g_ntc_app_plug.fs2_handle, comm_context->fs2_id, g_ntc_app_plug.statis_column_id[NTC_STATIS_C2S_BYTES], FS_OP_ADD, comm_context->c2s_bytes[NEW_VALUE]-comm_context->c2s_bytes[OLD_VALUE]);
			FS_operate(g_ntc_app_plug.fs2_handle, comm_context->fs2_id, g_ntc_app_plug.statis_column_id[NTC_STATIS_S2C_PKTS], FS_OP_ADD, comm_context->s2c_pkts[NEW_VALUE]-comm_context->s2c_pkts[OLD_VALUE]);
			FS_operate(g_ntc_app_plug.fs2_handle, comm_context->fs2_id, g_ntc_app_plug.statis_column_id[NTC_STATIS_S2C_BYTES], FS_OP_ADD, comm_context->s2c_bytes[NEW_VALUE]-comm_context->s2c_bytes[OLD_VALUE]);
			FS_operate(g_ntc_app_plug.fs2_handle, comm_context->fs2_id, g_ntc_app_plug.statis_column_id[NTC_STATIS_LINKS], FS_OP_ADD, comm_context->links[NEW_VALUE]-comm_context->links[OLD_VALUE]);
		}

		comm_context->c2s_pkts[OLD_VALUE] = comm_context->c2s_pkts[NEW_VALUE];
		comm_context->c2s_bytes[OLD_VALUE] = comm_context->c2s_bytes[NEW_VALUE];
		comm_context->s2c_pkts[OLD_VALUE] = comm_context->s2c_pkts[NEW_VALUE];
		comm_context->s2c_bytes[OLD_VALUE] = comm_context->s2c_bytes[NEW_VALUE];
	}

	comm_context->is_feedback = project_req_get_uint(pstream, g_ntc_app_plug.ssl_cons_label_id);	/* SSL */

	if(comm_context->is_feedback == RAW_FEEDBACK_START || comm_context->is_feedback == RAW_FEEDBACK_SSL)
	{
		switch(pstream->addr.addrtype)
		{
			case	ADDR_TYPE_IPV4:
			case	__ADDR_TYPE_IP_PAIR_V4:
				ip4 = (struct ip *)raw_pkt;
				rawpkt_len = ntohs(ip4->ip_len);
				v4ORv6 = PROTO_IPv4;
				break;
			case	ADDR_TYPE_IPV6:
			case	__ADDR_TYPE_IP_PAIR_V6:
				ip6 = (struct ip6_hdr *)raw_pkt;
				rawpkt_len = ntohs(ip6->ip6_plen)+40;
				v4ORv6 = PROTO_IPv6;
				break;
			default:
				return APP_STATE_DROPME;
				break;
		}
		
		if(comm_context->ddp_handle == NULL)
		{
			comm_context->ddp_handle = ddp_start(((comm_context->is_feedback==RAW_FEEDBACK_START) ? v4ORv6 : PROTO_SSL), pstream->threadnum);
		}

		ntc_feedback_rawpkt(comm_context->ddp_handle, pstream, raw_pkt, rawpkt_len);
	}
	
	return 0;
}

char NTC_SSL_LABEL_PLUG_ENTRY(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	int ret=-1,project_req_value = RAW_FEEDBACK_SSL;

	if((g_ntc_app_plug.is_feedback&IS_FEEDBACK_SSL)==0)
	{
		return APP_STATE_DROPME;
	}
	
	if(*pme == NULL)
	{
		*pme = (int *)calloc(1, sizeof(int));
		*(int *)(*pme) = RAW_FEEDBACK_SSL;
		
		project_req_value = RAW_FEEDBACK_SSL;
		ret = project_req_add_int(a_stream, g_ntc_app_plug.ssl_prod_label_id, project_req_value);
		if(ret < 0)
		{
			MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "SSL_ADD_LABEL", "project_req_add_int failed, label: %d", project_req_value);
		}
		else
		{
			MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_DEBUG, "SSL_ADD_LABEL", "project_req_add_int succ, label: %d", project_req_value);
		}
	}
	
	if(session_info->plugid == SSL_APPLICATION_DATA || session_info->session_state&SESSION_STATE_CLOSE)
	{
		free(*pme);
		*pme = NULL;
		project_req_value = RAW_FEEDBACK_STOP;
		ret = project_req_add_int(a_stream, g_ntc_app_plug.ssl_prod_label_id, project_req_value);
		if(ret < 0)
		{
			MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "SSL_ADD_LABEL", "project_req_add_int failed, label: %d", project_req_value);
 		}
		else
		{
			MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_DEBUG, "SSL_ADD_LABEL", "project_req_add_int succ, label: %d", project_req_value);
		}
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}

char NTC_APP_PLUG_TCP_ENTRY(const struct streaminfo *a_tcp,  void **pme, int thread_seq,const void *raw_pkt)
{
	comm_context_t *context = (comm_context_t *)*pme;
	
	switch(a_tcp->pktstate)
	{
		case	OP_STATE_PENDING:
			init_app_context(&context, thread_seq);
			*pme = (void *)context;
			context->links[NEW_VALUE]++;
			ntc_update_comm_context(a_tcp, context, PROTO_TCP, a_tcp->pktstate, g_ntc_app_plug.tcp_pkt_interval, raw_pkt);
			break;
		case	OP_STATE_DATA:
			ntc_update_comm_context(a_tcp, context, PROTO_TCP, a_tcp->pktstate, g_ntc_app_plug.tcp_pkt_interval, raw_pkt);
			if(context->is_feedback == RAW_FEEDBACK_STOP)
			{
				destroy_app_context(context, a_tcp->threadnum);
				return APP_STATE_DROPME;
			}
			break;
		case	OP_STATE_CLOSE:
			ntc_update_comm_context(a_tcp, context, PROTO_TCP, a_tcp->pktstate, g_ntc_app_plug.tcp_pkt_interval, raw_pkt);
			destroy_app_context(context, thread_seq);
			return APP_STATE_DROPME;
			break;
		default:
			assert(0);
	}

	return APP_STATE_GIVEME;
}

char NTC_APP_PLUG_UDP_ENTRY(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *raw_pkt)
{
	comm_context_t *context = (comm_context_t *)*pme;
	
	switch(a_udp->opstate)
	{
		case	OP_STATE_PENDING:
			init_app_context(&context, thread_seq);
			*pme = (void *)context;
			context->links[NEW_VALUE]++;
			ntc_update_comm_context(a_udp, context, PROTO_UDP, a_udp->opstate, g_ntc_app_plug.udp_pkt_interval, raw_pkt);
			break;
		case	OP_STATE_DATA:
			ntc_update_comm_context(a_udp, context, PROTO_UDP, a_udp->opstate, g_ntc_app_plug.udp_pkt_interval, raw_pkt);
			if(context->is_feedback == RAW_FEEDBACK_STOP)
			{
				destroy_app_context(context, a_udp->threadnum);
				return APP_STATE_DROPME;
			}
			break;
		case	OP_STATE_CLOSE:
			ntc_update_comm_context(a_udp, context, PROTO_UDP, a_udp->opstate, g_ntc_app_plug.udp_pkt_interval, raw_pkt);
			destroy_app_context(context, thread_seq);
			return APP_STATE_DROPME;
			break;
		default:
			assert(0);
	}

	return APP_STATE_GIVEME;
}


char NTC_GRE_IP_ENTRY(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const void *ip_hdr)
{
	int proto = 0;
	soq_protocol_t ddp_proto;
	struct ip6_hdr * ip6 = NULL;
	struct ip * ip4 = NULL;

	if((g_ntc_app_plug.is_feedback&IS_FEEDBACK_GRE)==IS_FEEDBACK_GRE || pstream == NULL)
	{
		return APP_STATE_DROPME;
	}
	
	switch(pstream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
		case	__ADDR_TYPE_IP_PAIR_V4:
			ip4 = (struct ip *)ip_hdr;
			proto = ip4->ip_p;
			ddp_proto = PROTO_IPv4;
			break;
		case	ADDR_TYPE_IPV6:
		case	__ADDR_TYPE_IP_PAIR_V6:
			ip6 = (struct ip6_hdr *)ip_hdr;
			proto = ip6->ip6_nxt;
			ddp_proto = PROTO_IPv6;
			break;
		default:
			return APP_STATE_DROPME;
			break;
	}

	if(proto == 47)	/* GRE */
	{
		ntc_feedback_single_rawpkt(pstream, ddp_proto);
	}

	return APP_STATE_GIVEME;
}


int NTC_APP_PLUG_INIT()
{
	int i=0, value=0;
	char ssl_project_name[128];
	char dkpt_project_name[128];
	const char* fs2_app_name="app_plug";
	const char* fs2_stat_path="./app_plug_statis.status";
	MESA_htable_create_args_t args;
	
	memset(&g_ntc_app_plug, 0, sizeof(g_ntc_app_plug));

	MESA_load_profile_int_def(app_profile, "APP_PLUG", "LOG_LEVAL", &g_ntc_app_plug.log_level, 30);
	MESA_load_profile_string_def(app_profile, "APP_PLUG", "LOG_PATH", g_ntc_app_plug.log_path, sizeof(g_ntc_app_plug.log_path), "./t1log/ntc_rawpkt_log");
	

	g_ntc_app_plug.log_handle = MESA_create_runtime_log_handle(g_ntc_app_plug.log_path, g_ntc_app_plug.log_level);
	if(g_ntc_app_plug.log_handle == NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...");
		return -1;
	}

	MESA_load_profile_int_def(app_profile, "APP_PLUG", "FEEDBACK_SWITCH", &g_ntc_app_plug.is_feedback, 0);
	MESA_load_profile_int_def(app_profile, "APP_PLUG", "TCP_PKT_INTERVAL", &g_ntc_app_plug.tcp_pkt_interval, 4);
	MESA_load_profile_int_def(app_profile, "APP_PLUG", "UDP_PKT_INTERVAL", &g_ntc_app_plug.udp_pkt_interval, 2);
	MESA_load_profile_string_def(app_profile, "APP_PLUG", "DKPT_PROJECT", dkpt_project_name, sizeof(dkpt_project_name), "");
	MESA_load_profile_string_def(app_profile, "APP_PLUG", "SSL_PROJECT", ssl_project_name, sizeof(ssl_project_name), NULL);

	g_ntc_app_plug.dpkt_cons_label_id = project_customer_register(dkpt_project_name, PROJECT_VAL_TYPE_STRUCT);
	if(g_ntc_app_plug.dpkt_cons_label_id < 0)
	{
		MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "APP_PLUG_INIT", 
			"project_customer_register failed, project_name: %s, project_type: %s", dkpt_project_name, PROJECT_VAL_TYPE_STRUCT);
		return -1;
	}

	g_ntc_app_plug.ssl_prod_label_id = project_producer_register(ssl_project_name, PROJECT_VAL_TYPE_INT, NULL);
	if(g_ntc_app_plug.ssl_prod_label_id < 0)
	{
		MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "APP_PLUG_INIT", 
			"project_producer_register failed, project_name: %s, project_type: %s", ssl_project_name, PROJECT_VAL_TYPE_INT);
		return -1;
	}

	g_ntc_app_plug.ssl_cons_label_id = project_customer_register(ssl_project_name, PROJECT_VAL_TYPE_INT);
	if(g_ntc_app_plug.ssl_cons_label_id < 0)
	{
		MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "APP_PLUG_INIT", 
			"project_customer_register failed, project_name: %s, project_type: %s", ssl_project_name, PROJECT_VAL_TYPE_INT);
		return -1;
	}

	MESA_load_profile_int_def(app_profile, "APP_PLUG", "MAX_FS2_LINE_NUM", &g_ntc_app_plug.statis_line_num, 4096);
	MESA_load_profile_int_def(app_profile, "APP_PLUG", "STAT_CYCLE", &g_ntc_app_plug.stat_cycle, 5);
	MESA_load_profile_int_def(app_profile, "APP_PLUG", "TELEGRAF_PORT", &g_ntc_app_plug.telegraf_port, 8215);
	MESA_load_profile_string_def(app_profile, "APP_PLUG", "TELEGRAF_IP", g_ntc_app_plug.telegaf_ip, sizeof(g_ntc_app_plug.telegaf_ip), NULL);

	g_ntc_app_plug.fs2_handle = FS_create_handle();
	FS_set_para(g_ntc_app_plug.fs2_handle, STATS_SERVER_IP, g_ntc_app_plug.telegaf_ip, strlen(g_ntc_app_plug.telegaf_ip)+1);
	FS_set_para(g_ntc_app_plug.fs2_handle, STATS_SERVER_PORT, &g_ntc_app_plug.telegraf_port, sizeof(g_ntc_app_plug.telegraf_port));
	
	FS_set_para(g_ntc_app_plug.fs2_handle, APP_NAME, fs2_app_name, strlen(fs2_app_name)+1);
	value=0;
	FS_set_para(g_ntc_app_plug.fs2_handle, FLUSH_BY_DATE, &value, sizeof(value));
	FS_set_para(g_ntc_app_plug.fs2_handle, OUTPUT_DEVICE, fs2_stat_path, strlen(fs2_stat_path)+1);
	value=1;
	FS_set_para(g_ntc_app_plug.fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=1;
	FS_set_para(g_ntc_app_plug.fs2_handle, CREATE_THREAD, &value, sizeof(value));
	FS_set_para(g_ntc_app_plug.fs2_handle, STAT_CYCLE, &g_ntc_app_plug.stat_cycle, sizeof(g_ntc_app_plug.stat_cycle));
	FS_set_para(g_ntc_app_plug.fs2_handle, MAX_STAT_FIELD_NUM, &g_ntc_app_plug.statis_line_num, sizeof(g_ntc_app_plug.statis_line_num));
	value=2;
	FS_set_para(g_ntc_app_plug.fs2_handle, STATS_FORMAT, &value, sizeof(value));

    for(i=0;i<NTC_STATIS_COLUMN_NUM;i++)
    {
		g_ntc_app_plug.statis_column_id[i] = FS_register(g_ntc_app_plug.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, ntc_statis_column[i]);
		if(g_ntc_app_plug.statis_column_id[i] < 0)
		{
			MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "FS2_INIT", "FS_register failed, column_name: %s", ntc_statis_column[i]);
			return -1;
		}
    }

	FS_start(g_ntc_app_plug.fs2_handle);

#if 0
	g_ntc_app_plug.table_id = Maat_table_register(g_t1_maat_feather, "APP_POLICY");
	if(g_ntc_app_plug.table_id < 0)
	{
		MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "MAAT_INIT_TABLE", "Maat_table_register failed, table name is APP_POLICY");
		return -1;
	}
#endif
	int max_thread_num = get_thread_count();
	g_ntc_app_plug.lhash_handle = (MESA_htable_handle *)calloc(32, sizeof(MESA_htable_handle));

	args.thread_safe = 0;
	args.recursive = 0;
	args.hash_slot_size = 8192;
	args.max_elem_num = 0;
	args.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	args.expire_time = 0;
	args.key2index = NULL;
	args.key_comp = NULL;
	args.data_free = free_buf;
	args.data_expire_with_condition = NULL;
	
	for(i=0; i<max_thread_num; i++)
	{
		g_ntc_app_plug.lhash_handle[i] = MESA_htable_create(&args, sizeof(args));
		if(g_ntc_app_plug.lhash_handle[i]== NULL)
		{
			MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "INIT_HASH", "MESA_htable_create failed, hash_index: %d", i);
			return -1;
		}
	}
	args.thread_safe = max_thread_num;
	args.recursive = 1;

	g_ntc_app_plug.ghash_handle = MESA_htable_create(&args, sizeof(args));
	if(g_ntc_app_plug.ghash_handle== NULL)
	{
		MESA_handle_runtime_log(g_ntc_app_plug.log_handle, RLOG_LV_FATAL, "INIT_HASH", "Init global hash failed");
		return -1;
	}
	
	return 0;
}


void NTC_APP_PLUG_DESTORY()
{
	
}

