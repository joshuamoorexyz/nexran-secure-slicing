
#include <chrono>
#include <string>
#include "rapidjson/prettywriter.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/filewritestream.h"
#include <cstdio>
#include <fstream>
#include<iostream>
#include "rapidjson/writer.h"
#include "mdclog/mdclog.h"
#include "rmr/RIC_message_types.h"
#include "ricxfcpp/message.hpp"
#include "ricxfcpp/messenger.hpp"
//#include "pistache/string_logger.h"
//#include "pistache/tcp.h"
#include<vector>
#include "nexran.h"
#include "e2ap.h"
#include "e2sm.h"
#include "e2sm_nexran.h"
#include "e2sm_kpm.h"
#include "e2sm_zylinium.h"
#include "restserver.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iterator> 



#include <ctime> // Include the header for date and time formatting
#include <thread> // Include the header for std::this_thread::sleep_for

#include "mdclog/mdclog.h"
#include "rmr/RIC_message_types.h"
#include "ricxfcpp/message.hpp"
#include "ricxfcpp/messenger.hpp"
//#include "pistache/string_logger.h"
//#include "pistache/tcp.h"

#include "nexran.h"
#include "e2ap.h"
#include "e2sm.h"
#include "e2sm_nexran.h"
#include "e2sm_kpm.h"
#include "e2sm_zylinium.h"
#include "restserver.h"
//#include "restserver.cc"

//#include "openai.hpp"



//#include "restserver.cc"
using namespace rapidjson;
using namespace std;

int TX_PKTS=0;
int TOTAL_TX_1=0;
int TOTAL_TX_2=0;
int COUNTER1=0;
int COUNTER2=0;
bool malicious=0;
bool slicecheck=0;
int tx_threshold = 304;
//int malicious = 0;
bool maliciousseventy = 0;
bool maliciousseventyone = 0;
int malue = 0;

std::vector<double> legit1ue = {1.0,74475.0, 72798.0, 3064.0, 1264.0, 6663314.0, 6527328.0, 108524.0, 52676.0, 74475.0, 72798.0, 3064.0, 1264.0, 306.0, 0.0, 0.0, 0.0, 10927200.0, 0.0, 57.0, 0.0, 0.0, 0.0, 288288.0, 0.0, 15.0, 15.0, 0.0, 0.0, 0.0, 0.0, 30.0, 0.0, 116.571, 0.0, 23.4375, 0.0, 135.0, 0.0, 28.0, 0.0};
std::vector<double> legit2ue = {2.0,89703.0, 44283.0, 4032.0, 1671.0, 7947136.0, 4351222.0, 148072.0, 51220.0, 89703.0, 44283.0, 4032.0, 1671.0, 653.0, 0.0, 0.0, 0.0, 23451912.0, 0.0, 93.0, 0.0, 0.0, 0.0, 339256.0, 0.0, 15.0, 0.0, 0.0, 0.0, 0.0, 0.0, 30.0, 0.0, 117.972, 0.0, 23.0, 0.0, 176.0, 0.0, 28.0, 0.0};






std::string slice1 = "fast";
std::string slice2 = "secure_slice";

std::string ue1imsi = "NULL";
std::string ue2imsi = "NULL";

namespace nexran {

static void rmr_callback(
    xapp::Message &msg,int mtype,int subid,int payload_len,
    xapp::Msg_component payload,void *data)
{
    ((App *)data)->handle_rmr_message(
        msg,mtype,msg.Get_subid(),payload_len,payload);
}

void App::handle_rmr_message(
    xapp::Message &msg,int mtype,int subid,int payload_len,
    xapp::Msg_component &payload)
{
    mdclog_write(MDCLOG_DEBUG,"RMR message (type %d, source %s)",
		 mtype,msg.Get_meid().get());

    switch (mtype) {
    case RIC_SUB_REQ:
    case RIC_SUB_RESP:
    case RIC_SUB_FAILURE:
    case RIC_SUB_DEL_REQ:
    case RIC_SUB_DEL_RESP:
    case RIC_SUB_DEL_FAILURE:
    case RIC_SERVICE_UPDATE:
    case RIC_SERVICE_UPDATE_ACK:
    case RIC_SERVICE_UPDATE_FAILURE:
    case RIC_CONTROL_REQ:
    case RIC_CONTROL_ACK:
    case RIC_CONTROL_FAILURE:
    case RIC_INDICATION:
    case RIC_SERVICE_QUERY:
	break;
    default:
	mdclog_write(MDCLOG_WARN,"unsupported RMR message type %d",mtype);
	return;
    } 

    e2ap.handle_message(payload.get(),payload_len,subid,
			std::string((char *)msg.Get_meid().get()),
			std::string((char *)msg.Get_xact().get()));

    return;
}

bool App::send_message(const unsigned char *buf,ssize_t buf_len,
		       int mtype,int subid,const std::string& meid,
		       const std::string& xid)
{
    std::unique_ptr<xapp::Message> msg = Alloc_msg(buf_len);
    msg->Set_mtype(mtype);
    msg->Set_subid(subid);
    msg->Set_len(buf_len);
    xapp::Msg_component payload = msg->Get_payload();
    memcpy((char *)payload.get(),(char *)buf,
	   ((msg->Get_available_size() < buf_len)
	    ? msg->Get_available_size() : buf_len));
    std::shared_ptr<unsigned char> msg_meid((unsigned char *)strdup(meid.c_str()));
    msg->Set_meid(msg_meid);
    if (!xid.empty()) {
	std::shared_ptr<unsigned char> msg_xid((unsigned char *)strdup(xid.c_str()));
	msg->Set_xact(msg_xid);
    }
    return msg->Send();
}

/*
 * These handlers work at the App level.  The E2AP request tracking
 * library stores requests and watches for responses, and by the time
 * these handlers are invoked, it has constructed that mapping for us.
 * These handlers map request/response pairs to RequestGroups that came
 * from the northbound interface.
 */
bool App::handle(e2ap::SubscriptionResponse *resp)
{
    mdclog_write(MDCLOG_DEBUG,"nexran SubscriptionResponse handler");
}

bool App::handle(e2ap::SubscriptionFailure *resp)
{
    mdclog_write(MDCLOG_DEBUG,"nexran SubscriptionFailure handler");
}

bool App::handle(e2ap::SubscriptionDeleteResponse *resp)
{
    mdclog_write(MDCLOG_DEBUG,"nexran SubscriptionDeleteResponse handler");
}

bool App::handle(e2ap::SubscriptionDeleteFailure *resp)
{
    mdclog_write(MDCLOG_DEBUG,"nexran SubscriptionDeleteFailure handler");
}
    
bool App::handle(e2ap::ControlAck *control)
{
    mdclog_write(MDCLOG_DEBUG,"nexran ControlAck handler");
}

bool App::handle(e2ap::ControlFailure *control)
{
    mdclog_write(MDCLOG_DEBUG,"nexran ControlFailure handler");
}

bool App::handle(e2ap::Indication *ind)
{
    bool retval = false;

    mdclog_write(MDCLOG_DEBUG,"nexran Indication handler");
    if (ind->model) {
	e2sm::kpm::KpmIndication *kind;
	e2sm::nexran::SliceStatusIndication *nind;
	e2sm::zylinium::MaskStatusIndication *zind;

	if ((kind = dynamic_cast<e2sm::kpm::KpmIndication *>(ind->model)) != NULL)
	    retval = handle(kind);
	else if ((nind = dynamic_cast<e2sm::nexran::SliceStatusIndication *>(ind->model)) != NULL)
	    retval = handle(nind);
	else if ((zind = dynamic_cast<e2sm::zylinium::MaskStatusIndication *>(ind->model)) != NULL)
	    retval = handle(zind);
    }

    delete ind;
    return retval;
}

bool App::handle(e2ap::ErrorIndication *ind)
{
    mdclog_write(MDCLOG_DEBUG,"nexran ErrorIndication handler");
}

bool App::handle(e2sm::nexran::SliceStatusIndication *ind)
{
    mdclog_write(MDCLOG_DEBUG,"nexran SliceStatusIndication handler");
    std::string rname;

    if (ind->parent && ind->parent->subscription_request != nullptr) {
	rname = ind->parent->subscription_request->meid;
	mutex.lock();
	if (db[ResourceType::NodeBResource].count(rname) > 0) {
	    NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][rname];
	    nodeb->update_last_indication();
	}
	mutex.unlock();
    }
}

/// @brief sudo docker build . -t xApp-registry.local:5008/nexran:0.1.0

/// @param kind 
/// @return
//
//


//struct for Metric array
struct Metric {
	double numericValue;
	std::string stringValue;
};

bool App::handle(e2sm::kpm::KpmIndication *kind)
{
    mdclog_write(MDCLOG_INFO,"KpmIndication: %s",
		 kind->report->to_string('\n',',').c_str());

    e2sm::kpm::KpmReport *report = kind->report;
    std::string rname;

//metricArray storing each kpm report
    std::vector<Metric> metricArray;

	//numuevector
	std::vector<Metric> UEArray;


    if (kind->parent && kind->parent->subscription_request != nullptr) {
	rname = kind->parent->subscription_request->meid;
	mutex.lock();
	if (db[ResourceType::NodeBResource].count(rname) > 0) {
	    NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][rname];
	    nodeb->update_config(report->available_ul_prbs);
	    nodeb->update_last_indication();
	}
	mutex.unlock();
    }

    if (influxdb && (report->slices.size() || report->ues.size())) {
	influxdb->batchOf(report->slices.size() + report->ues.size());
	for (auto it = report->slices.begin(); it != report->slices.end(); ++it) {

	    influxdb->write(influxdb::Point{"slice"}
		.addField("dl_bytes", (long long int)it->second.dl_bytes)
		.addField("ul_bytes", (long long int)it->second.ul_bytes)
		.addField("dl_prbs", (long long int)it->second.dl_prbs)
		.addField("ul_prbs", (long long int)it->second.ul_prbs)
		.addField("tx_pkts", (long long int)it->second.tx_pkts)
		.addField("tx_errors", (long long int)it->second.tx_errors)
		.addField("tx_brate", (long long int)it->second.tx_brate)
		.addField("rx_pkts", (long long int)it->second.rx_pkts)
		.addField("rx_errors", (long long int)it->second.rx_errors)
		.addField("rx_brate", (long long int)it->second.rx_brate)
		.addField("dl_cqi", it->second.dl_cqi)
		.addField("dl_ri", it->second.dl_ri)
		.addField("dl_pmi", it->second.dl_pmi)
		.addField("ul_phr", it->second.ul_phr)
		.addField("ul_sinr", it->second.ul_sinr)
		.addField("ul_mcs", it->second.ul_mcs)
		.addField("ul_samples", (long long int)it->second.ul_samples)
		.addField("dl_mcs", it->second.dl_mcs)
		.addField("dl_samples", (long long int)it->second.dl_samples)
		.addTag("slice", it->first.c_str())
		.addTag("nodeb", rname.c_str()));
	}
	
	for (auto it = report->ues.begin(); it != report->ues.end(); ++it) {


       	 // Create a Metric instance for each metric and store in the array
	    
	    influxdb->write(influxdb::Point{"ue"}
		.addField("dl_bytes", (long long int)it->second.dl_bytes)
		.addField("ul_bytes", (long long int)it->second.ul_bytes)
		.addField("dl_prbs", (long long int)it->second.dl_prbs)
		.addField("ul_prbs", (long long int)it->second.ul_prbs)
		.addField("tx_pkts", (long long int)it->second.tx_pkts)
		.addField("tx_errors", (long long int)it->second.tx_errors)
		.addField("tx_brate", (long long int)it->second.tx_brate)
		.addField("rx_pkts", (long long int)it->second.rx_pkts)
		.addField("rx_errors", (long long int)it->second.rx_errors)
		.addField("rx_brate", (long long int)it->second.rx_brate)
		.addField("dl_cqi", it->second.dl_cqi)
		.addField("dl_ri", it->second.dl_ri)
		.addField("dl_pmi", it->second.dl_pmi)
		.addField("ul_phr", it->second.ul_phr)
		.addField("ul_sinr", it->second.ul_sinr)
	    .addField("ul_mcs", it->second.ul_mcs)
		.addField("ul_samples", (long long int)it->second.ul_samples)
		.addField("dl_mcs", it->second.dl_mcs)
		.addField("dl_samples", (long long int)it->second.dl_samples)
		.addTag("ue", std::to_string(it->first).c_str())
		.addTag("nodeb", rname.c_str()));

		
		//mdclog_write(MDCLOG_INFO, "Numeric Value: %lld, String Value: %s", nodebnameMetric.numericValue, nodebnameMetric.stringValue.c_str());
	   // mdclog_write(MDCLOG_INFO, "Nodeb name: %s", rname.c_str());
	}
	try {
	    influxdb->flushBatch();
	}
	catch (...) {
	    mdclog_write(MDCLOG_ERR,"failed to write KPM points to influxdb");
	}
    }

    // If we don't have BW reports for all slices, do not modify proportions?
    // Add up all slice dl_bytes, get proportions
    // map those to share proportions
    // figure out the delta for each slice to equalize
    // 10, 5, 10 // 512, 512, 512
    // new target: (25/3)=8.333... for each
    // 25/3-10=-1.667, 25/3-5=3.333, 25/3-10=-1.667
    // -1.667/10 == -16.67% (apply that to current share, so remove 16.67%
    // of its share, and so on)
    // new shares: 512+(512*-.1667) = 426
    //             512+(512*.6667) = 853
    //             512+(512*-.1667) = 426
    // If all share factors are within 5%, make no changes.
    
    // ugh, this is also assuming a single nodeb, because our slice
    // share policy is global, not per nodeb
    
    // but -- we could also keep a per-nodeb specialization :-D
    // maybe hide it from user, who knows




    if (report->slices.size() == 0) {
	mdclog_write(MDCLOG_DEBUG,"no slices in KPM report; not autoequalizing");
	if (mdclog_level_get() == MDCLOG_DEBUG) {
	    mutex.lock();
	    std::stringstream ss;
	    for (auto it = db[ResourceType::SliceResource].begin();
		 it != db[ResourceType::SliceResource].end();
		 ++it) {
		Slice *slice = (Slice *)it->second;
		if (dynamic_cast<ProportionalAllocationPolicy *>(slice->getPolicy()) == NULL)
		    continue;
		ProportionalAllocationPolicy *policy = \
		    dynamic_cast<ProportionalAllocationPolicy *>(slice->getPolicy());
		if (false && !policy->isAutoEqualized())
		    continue;
		ss << it->first << "[share=" << policy->getShare() << "]" << std::endl;
	    }
	    mutex.unlock();
	    mdclog_write(MDCLOG_DEBUG,"current shares: %s",ss.str().c_str());
	}
	return true;
    }



//print the vector for viewing

//mdclog_write(MDCLOG_INFO, "Size : %d",metricArray.size());


//clear the metricArray after sending
metricArray.clear();
UEArray.clear();





    // Have to lock at this point; we're going to iterate over
    // and possibly adjust the slice cArray.clear();
    // proportions.
    mutex.lock();

    // Index some stuff locally for easier iteration; save share modification factors.
    std::map<std::string,Slice *> slices;
    std::map<std::string,Slice *> report_slices;
    std::map<std::string,ProportionalAllocationPolicy *> policies;
    std::map<std::string,float> new_share_factors;
    //std::map<std::string,int> new_shares;
    uint64_t slices_total = 0;
    uint64_t slices_prb_total = 0;

    // Create local indexes.
    for (auto it = db[ResourceType::SliceResource].begin(); it != db[ResourceType::SliceResource].end(); ++it) {
	std::string slice_name = it->first;

	Slice *slice = (Slice *)it->second;
	ProportionalAllocationPolicy *policy = \
	    dynamic_cast<ProportionalAllocationPolicy *>(slice->getPolicy());
	if (!policy)
	    continue;




//if the policy is false or null, the loop iteration is skipped using continue. 
//Otherwise, the slice, policy, and new_share_factors values are assigned to their respective maps for further processing.


	slices[slice_name] = slice;
	policies[slice_name] = policy;
	// placeholder until later iteration
	new_share_factors[slice_name] = 0.0f;
    }

    int num_autoeq_slices = 0;
    for (auto it = report->slices.begin(); it != report->slices.end(); ++it) {
	std::string slice_name = it->first;
	// If this is not a slice we know of, ignore.
	if (slices.count(slice_name) == 0)
	    continue;
	Slice *slice = (Slice *)slices[slice_name];
	ProportionalAllocationPolicy *policy = \
	    dynamic_cast<ProportionalAllocationPolicy *>(slice->getPolicy());
	if (!policy)
	    continue;

	report_slices[slice_name] = slice;

	// NB: only auto-eq amongst metrics for auto-eq'd slices.
	// XXX: is this right?
	if (policy->isAutoEqualized()) {
	    slices_total += it->second.dl_bytes;
	    slices_prb_total += it->second.dl_prbs;
	    ++num_autoeq_slices;
	}

	policy->getMetrics().add(it->second);
    }

    // First, check if any slices should be released from throttling.
    for (auto it = slices.begin(); it != slices.end(); ++it) {
	std::string slice_name = it->first;
	Slice *slice = (Slice *)it->second;
	ProportionalAllocationPolicy *policy = policies[slice_name];
	if (!policy->isThrottled() || !policy->isThrottling())
	    continue;

	// Ensure we flush old metrics, even if we didn't add any new ones
	// from the current report.
	policy->getMetrics().flush();

	int new_share = policy->maybeEndThrottling();
	if (new_share > -1) {
	    mdclog_write(MDCLOG_DEBUG,"stopping throttling slice '%s' (%d -> %d)",
			 slice_name.c_str(),policy->getShare(),new_share);
	    // NB: we just compute a share factor, because that's what the
	    // auto-equalizing code cares about.
	    // nshare = cshare + (cshare * f)
	    // n - c = c * f
	    // (n - c) / c = f
	    // 110 = 100 + 100 * .1
	    // (110 - 100) / 100 = f
	    int cur_share = policy->getShare();
	    new_share_factors[slice_name] = (new_share - cur_share) / (float)cur_share;
	}
	else {
	    new_share = policy->maybeUpdateThrottling();
	    if (new_share > -1 && new_share != policy->getShare()) {
		int cur_share = policy->getShare();
		new_share_factors[slice_name] = (new_share - cur_share) / (float)cur_share;
	    }
	}
    }

    // Second, check if any slices should be newly throttled.
    for (auto it = slices.begin(); it != slices.end(); ++it) {
	std::string slice_name = it->first;

	Slice *slice = (Slice *)it->second;
	ProportionalAllocationPolicy *policy = policies[slice_name];
	if (!policy->isThrottled() || policy->isThrottling())
	    continue;

	// Ensure we flush old metrics, even if we didn't add any new ones
	// from the current report.
	e2sm::kpm::MetricsIndex& metrics = policy->getMetrics();
	mdclog_write(MDCLOG_DEBUG,"considering throttle start for slice '%s': %ld (%d)",
		     slice_name.c_str(),metrics.get_total_bytes(),metrics.size());
	metrics.flush();
	mdclog_write(MDCLOG_DEBUG,"considering throttle start for slice '%s': %ld (%d) (post flush)",
		     slice_name.c_str(),metrics.get_total_bytes(),metrics.size());

	int new_share = policy->maybeStartThrottling();
	if (new_share > -1) {
	    mdclog_write(MDCLOG_DEBUG,"starting throttling slice '%s' (%d -> %d)",
			 slice_name.c_str(),policy->getShare(),new_share);
	    // NB: we just compute a share factor, because that's what the
	    // auto-equalizing code cares about.
	    int cur_share = policy->getShare();
	    new_share_factors[slice_name] = (new_share - cur_share) / (float)cur_share;
	}
    }

    // Begin auto-equalize checks.
    bool any_above_threshold = false;
    uint64_t available_prbs_per_slice = 0;
    if (num_autoeq_slices > 0)
	available_prbs_per_slice = (report->period_ms * 2 * report->available_dl_prbs) / num_autoeq_slices;
    uint64_t prb_threshold = (uint64_t)(0.15f * available_prbs_per_slice);

    if (available_prbs_per_slice > 0) {
	// Check PRB utilization.  If no slice has utilized at least 15% of an
	// even PRB allocation, do nothing.
	for (auto it = report_slices.begin(); it != report_slices.end(); ++it) {
	    std::string slice_name = it->first;
	    uint64_t dl_prbs = report->slices[slice_name].dl_prbs;

	    if (dl_prbs > prb_threshold) {
		any_above_threshold = true;
		break;
	    }

	}
    }


    // Create the new share factors.
    if (any_above_threshold) {
	mdclog_write(MDCLOG_INFO,"PRB utilization threshold (%lu/%lu) reached; checking for new share factors",
		     prb_threshold,available_prbs_per_slice);
	any_above_threshold = false;
	for (auto it = report_slices.begin(); it != report_slices.end(); ++it) {
	    std::string slice_name = it->first;
	    uint64_t dl_bytes = report->slices[slice_name].dl_bytes;
	    ProportionalAllocationPolicy *policy = policies[slice_name];
	    if (!policy->isAutoEqualized()) {
		mdclog_write(MDCLOG_DEBUG,"skipping slice '%s'; not autoequalized",
			     slice_name.c_str());
		continue;
	    }

	    if (new_share_factors[slice_name] != 0.0f) {
		mdclog_write(MDCLOG_DEBUG,"skipping slice '%s' with existing new_share_factor %f",
			     slice_name.c_str(),new_share_factors[slice_name]);
		continue;
	    }

	    float nf = ((float)slices_total / num_autoeq_slices - dl_bytes) / dl_bytes;
	    if (nf > 0.05f || nf < -0.05f) {
		any_above_threshold = true;
		mdclog_write(MDCLOG_DEBUG,"candidate proportional share factor above threshold (%s): %f",
			     slice_name.c_str(),nf);
	    }
	    else
		mdclog_write(MDCLOG_DEBUG,"candidate proportional share factor below threshold (%s): %f",
			     slice_name.c_str(),nf);

	}
    }

    // XXX: have to do a second time through the loop to actually set the
    // new share factors, sigh

	//int tx_pkts=0;
	//int total_tx_pkts=0;

    if (any_above_threshold) {
	for (auto it = report->slices.begin(); it != report->slices.end(); ++it) {
	    std::string slice_name = it->first;
	    uint64_t dl_bytes = report->slices[slice_name].dl_bytes;
	    if (policies.count(slice_name) == 0)
		continue;
	    ProportionalAllocationPolicy *policy = policies[slice_name];
	    if (!policy->isAutoEqualized())
		continue;

	    if (new_share_factors[slice_name] != 0.0f)

		continue;

	    new_share_factors[slice_name] = ((float)slices_total / num_autoeq_slices - dl_bytes) / dl_bytes;
	    mdclog_write(MDCLOG_DEBUG,"new proportional share factor (%s): %f",
			 slice_name.c_str(),new_share_factors[slice_name]);
	
	}
    }

//hsdbhbdfhjhbdgufhdjhjfsdhoiugjfidsjgoijsdfijgi
//jkdsngjdfkgjfdskjgsd
//djgjdfhjgkfdskgkdjsgk
//dkjsnhgjdhufshsgusfdjg
//kjdfkgsjfkgsdfkljfg
//sdkgjfsdhjakhjks
//fdjhsjghfdgjksdfkg
//dsfjgjkdfshg sdjg
//fsdkjgksdfkgfdg

//get the number of UE currently connected. should we empty later idk
int ueCount = static_cast<int>(std::distance(report->ues.begin(), report->ues.end()));



for (auto it = report->ues.begin(); it != report->ues.end(); ++it) {
		





	//    Metric uenameMetric;
   	//    uenameMetric.numericValue = ueCount;
	//    //uenameMetric.stringValue = std::to_string(it->first).c_str();
	//    metricArray.push_back(uenameMetric);
	//    UEArray.push_back(uenameMetric);
	//    mdclog_write(MDCLOG_INFO, "Number of UEs: %f", uenameMetric.numericValue);




	// 	 // Create a Metric instance for each metric and store in the array
	//     Metric dlBytesMetric;
    //     dlBytesMetric.numericValue = (double)it->second.dl_bytes;
	//     //dlBytesMetric.stringValue = "dl_bytes";
    //     metricArray.push_back(dlBytesMetric);
	// 	UEArray.push_back(dlBytesMetric);


    //    Metric ulBytesMetric;
    //    ulBytesMetric.numericValue = (double)it->second.ul_bytes;
	//    //ulBytesMetric.stringValue = "ul_bytes";
	//    metricArray.push_back(ulBytesMetric);
	//    UEArray.push_back(ulBytesMetric);
 


	//    Metric dlprbsMetric;
	//    dlprbsMetric.numericValue = (double)it->second.dl_prbs;
	//    //dlprbsMetric.stringValue = "dl_prbs";
	//    metricArray.push_back(dlprbsMetric);
	//    UEArray.push_back(dlprbsMetric);


	//    Metric ulprbsMetric;
	//    ulprbsMetric.numericValue = (double)it->second.ul_prbs;
	//    //ulprbsMetric.stringValue = "ul_prbs";
	//    metricArray.push_back(ulprbsMetric);
	//    UEArray.push_back(ulprbsMetric);



		
	   Metric txpktsMetric;
   	   txpktsMetric.numericValue = (double)it->second.tx_pkts;
	   //txpktsMetric.stringValue = "tx_pkts";
	   metricArray.push_back(txpktsMetric);
	   UEArray.push_back(txpktsMetric);


	//    Metric txerrorsMetric;
   	//    txerrorsMetric.numericValue = (double)it->second.tx_errors;
	//    //txerrorsMetric.stringValue = "tx_errors";
	//    metricArray.push_back(txerrorsMetric);
	//    UEArray.push_back(txerrorsMetric);


	//    Metric rxpktsMetric;
   	//    rxpktsMetric.numericValue = (double)it->second.rx_pkts;
	//    //rxpktsMetric.stringValue = "rx_pkts";
	//    metricArray.push_back(rxpktsMetric);
	//    UEArray.push_back(rxpktsMetric);


	//    Metric rxerrorsMetric;
   	//    rxerrorsMetric.numericValue = (double)it->second.rx_errors;
	//    //rxerrorsMetric.stringValue = "rx_errors";
	//    metricArray.push_back(rxerrorsMetric);
	//    UEArray.push_back(rxerrorsMetric);


	   
	//    Metric txbrateMetric;
   	//    txbrateMetric.numericValue = (double)it->second.tx_brate;
	//    //txbrateMetric.stringValue = "tx_brate";
	//    metricArray.push_back(txbrateMetric);





	//    Metric rxbrateMetric;
   	//    rxbrateMetric.numericValue = (double)it->second.rx_brate;
	//    //rxbrateMetric.stringValue = "rx_brate";
	//    metricArray.push_back(rxbrateMetric);
	//    UEArray.push_back(rxbrateMetric);


	//    Metric dlcqiMetric;
   	//    dlcqiMetric.numericValue = (double)it->second.dl_cqi;
	//    //dlcqiMetric.stringValue = "dl_cqi";
	//    metricArray.push_back(dlcqiMetric);
	//    UEArray.push_back(dlcqiMetric);

	   
	//    Metric dlriMetric;
   	//    dlriMetric.numericValue = (double)it->second.dl_ri;
	//    //dlriMetric.stringValue = "dl_ri";
	//    metricArray.push_back(dlriMetric);
	//    UEArray.push_back(dlriMetric);




	//    Metric dlpmiMetric;
   	//    dlpmiMetric.numericValue = (double)it->second.dl_pmi;
	//    //dlpmiMetric.stringValue = "dl_pmi";
	//    metricArray.push_back(dlpmiMetric);
	//    UEArray.push_back(dlpmiMetric);




	//    Metric ulphrMetric;
   	//    ulphrMetric.numericValue = (double)it->second.ul_phr;
	//    //ulphrMetric.stringValue = "ul_phr";
	//    metricArray.push_back(ulphrMetric);
	//    UEArray.push_back(ulphrMetric);




    //    Metric ulsinrMetric;
   	//    ulsinrMetric.numericValue = (double)it->second.ul_sinr;
	//    //ulsinrMetric.stringValue = "ul_sinr";
	//    metricArray.push_back(ulsinrMetric);
	//    UEArray.push_back(ulsinrMetric);




	//    Metric ulmcsMetric;
   	//    ulmcsMetric.numericValue = (double)it->second.ul_mcs;
	//    //ulmcsMetric.stringValue = "ul_mcs";
	//    metricArray.push_back(ulmcsMetric);
	//    UEArray.push_back(ulmcsMetric);

           


	//    Metric ulsamplesMetric;
   	//    ulsamplesMetric.numericValue = (double)it->second.ul_samples;
	//    //ulsamplesMetric.stringValue = "ul_samples";
	//    metricArray.push_back(ulsamplesMetric);
	//    UEArray.push_back(ulsamplesMetric);




	//    Metric dlmcsMetric;
   	//    dlmcsMetric.numericValue = (double)it->second.dl_mcs;
	//    //dlmcsMetric.stringValue = "dl_mcs";
	//    metricArray.push_back(dlmcsMetric);
	//    UEArray.push_back(dlmcsMetric);

		/*
		openai::start();

			// Define input values
			int ueCount = 1;
			double txPackets = 421.0;
			double dlCQI = 442688.0;
			double rxErrors = 93.0;

			// Create the user message with dynamic values
			std::string user_message = "Given the upper bounds for a " + std::to_string(ueCount) + " UE (user equipment) network as 'num_ue: " + std::to_string(ueCount) +
									"', 'TX Packets: " + std::to_string(txPackets) +
									"', DL CQI: " + std::to_string(dlCQI) +
									"', RX Errors: " + std::to_string(rxErrors) +
									", please evaluate the newly provided inputs 'num_ue: " + std::to_string(ueCount) +
									"', 'TX Packets: " + std::to_string((double)it->second.tx_pkts) +
									"', DL CQI: " + std::to_string((double)it->second.dl_cqi) +
									"', RX Errors: " + std::to_string((double)it->second.rx_errors) +
									"' to determine if they are within the specified bounds. Let's work this out in a step-by-step way to be sure we have the right answer. Only provide a one-word output, either 'Malicious' or 'Legitimate.";

   auto chat = openai::chat().create({
        {"model", "gpt-3.5-turbo"},
        {"messages", {
            {{"role", "user"}, {"content", user_message }}
        }},
        {"max_tokens", 50},
        {"temperature", 0.7}
    });

    std::string responseText = chat["choices"][0]["message"]["content"];

    mdclog_write(MDCLOG_INFO, "Response is: %s", chat.dump(2).c_str());

    // Check if the response contains "Malicious"
    if (responseText.find("Malicious") != std::string::npos) {
        // Mark the UE as Malicious
        mdclog_write(MDCLOG_INFO, "UE is Malicious");
    } else {
        // Mark the UE as Legitimate
        mdclog_write(MDCLOG_INFO, "UE is Legitimate");
    }
	
			
	*/
	//    Metric dlsamplesMetric;
   	//    dlsamplesMetric.numericValue = (double)it->second.dl_samples;
	//    //dlsamplesMetric.stringValue = "dl_samples";
	//    metricArray.push_back(dlsamplesMetric);



	//    Metric nodebnameMetric;
   	//    nodebnameMetric.numericValue = 0;
	//    nodebnameMetric.stringValue = rname.c_str();
	//    metricArray.push_back(nodebnameMetric);
	//    mdclog_write(MDCLOG_INFO, "Numeric Value: %lld, String Value: %s", nodebnameMetric.numericValue, nodebnameMetric.stringValue.c_str());
	//    mdclog_write(MDCLOG_INFO, "Nodeb name: %s", rname.c_str());
	    

   //Serialize the metricArray to JSON
    rapidjson::Document document;
    document.SetArray();


   // Add your metric data to the metricArray


   //send number of UEs to the python program

for (const Metric& metric : UEArray) {
    rapidjson::Value metricObject(rapidjson::kObjectType);
    metricObject.AddMember("numericValue", static_cast<double>(metric.numericValue), document.GetAllocator());
    metricObject.AddMember("stringValue", rapidjson::StringRef(metric.stringValue.c_str()), document.GetAllocator());
    document.PushBack(metricObject, document.GetAllocator());
}

rapidjson::StringBuffer buffer;
rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
document.Accept(writer);
std::string jsonStr = buffer.GetString();

// Send the JSON data over the network
const char* serverIP = "130.18.64.173";  // Replace with your server's IP address
int serverPort = 12345;


int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in serverAddr;
serverAddr.sin_family = AF_INET;
serverAddr.sin_port = htons(serverPort);
serverAddr.sin_addr.s_addr = inet_addr(serverIP);  // Use the server's IP address
connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
send(clientSocket, jsonStr.c_str(), jsonStr.size(), 0);





//Receive and log data from the server using mcdlog
char buffer1[1024];  // Adjust the buffer size as needed
ssize_t bytesRead = recv(clientSocket, buffer1, sizeof(buffer1), 0);
mdclog_write(MDCLOG_DEBUG, "I created bytes.");



//start the timer ( detection time)
auto start_time = std::chrono::high_resolution_clock::now();
std::time_t start_time_t = std::chrono::system_clock::to_time_t(start_time);
mdclog_write(MDCLOG_DEBUG, "Start time (detection): %s", std::ctime(&start_time_t));



//Convert the received bytes to a string
std::string bytesReceived(buffer1, bytesRead);
mdclog_write(MDCLOG_DEBUG, "Bytes recieved %s", bytesReceived.c_str());

bool isMalicious = (bytesReceived.find("Malicious") != std::string::npos);
mdclog_write(MDCLOG_DEBUG, "Tx Pkts VALUEEEEE %f", txpktsMetric.numericValue);

// Start the timer (response time)
auto response_start_time = std::chrono::high_resolution_clock::now();
std::time_t response_start_time_t = std::chrono::system_clock::to_time_t(response_start_time);
mdclog_write(MDCLOG_DEBUG, "Start time (response): %s", std::ctime(&response_start_time_t));

if (isMalicious)
{
		mdclog_write(MDCLOG_DEBUG, "I received Malicious Bytes");
	        mdclog_write(MDCLOG_DEBUG, "Tx threshold: %d", tx_threshold);
        if ((double)txpktsMetric.numericValue >= (double)tx_threshold) 
	{


                int ue_name = it->first;
                mdclog_write(MDCLOG_INFO,"UE  '%d' is Malicious:",ue_name);
				malicious = 1;
				malue = ue_name;

					
				//stop the timer
				auto end_time = std::chrono::high_resolution_clock::now();

				// Calculate the elapsed time
				auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

				// Get the current date and time for logging
				std::time_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

				// Log the elapsed time and current date/time using mdclog
				mdclog_write(MDCLOG_DEBUG, "Elapsed time (detection): %ld microseconds at %s", elapsed_time.count(), std::ctime(&current_time));
   

	}	
}
else
	
{
		mdclog_write(MDCLOG_DEBUG, "Malicious is set to 0 ");
        int ue_name = it->first;
         mdclog_write(MDCLOG_INFO,"UE  '%d' is Legitimate:",ue_name);
		malicious = 0;

}	



//Split the received data into individual numerical values
std::vector<double> numericData;
std::istringstream iss(bytesReceived);
std::string word;
int wordCount = 0;

while (iss >> word) {
   

    bool isNumeric = true;
    for (char c : word) {
        if (!std::isdigit(c) && c != '.' && c != '-') {
            isNumeric = false;
            break;
        }
    }

    if (isNumeric) {
        double value = std::stod(word);
        numericData.push_back(value);
    }
}

// 
//Check if you need to resize the array (vector)
if (numericData.size() < 2) {
    mdclog_write(MDCLOG_DEBUG, "The array needs to be resized.");
}

// Print the extracted data
for (const double& num : numericData) {
    mdclog_write(MDCLOG_DEBUG, "Received numerical data: %f", num);

}

close(clientSocket);




//print the metricArray to see if can be compared


    // for (long long int num : UEArray) {
    //     mdclog_write(MDCLOG_DEBUG, "metricArray: %lld", num);
    // }

	
    for (const nexran::Metric& metric : metricArray) {
        double num = metric.numericValue;
        mdclog_write(MDCLOG_DEBUG, "MetricArray: %f", num);
    }
	


		metricArray.clear();
		
		int ue_name = it->first;
		mdclog_write(MDCLOG_INFO,"UE NAME '%d':",ue_name);
		
		if(ue_name==70) 
		{
			//total the tx pkts for ue1
			TOTAL_TX_1 = TOTAL_TX_1+ report->ues[ue_name].tx_pkts;
			mdclog_write(MDCLOG_INFO, "Total tx_pkts '%d': %d",
			ue_name, TOTAL_TX_1);
			COUNTER1++;
			mdclog_write(MDCLOG_INFO,"COUNT: %d",
			COUNTER1);
			mdclog_write(MDCLOG_INFO,"Malicious: %d. I am UE 70",maliciousseventy);

		}

		else if(ue_name==72) 
		{
			TOTAL_TX_2 = TOTAL_TX_2 + report->ues[ue_name].tx_pkts;
			mdclog_write(MDCLOG_INFO, "Total tx_pkts '%d': %d",
			ue_name, TOTAL_TX_2);
			COUNTER2++;
			mdclog_write(MDCLOG_INFO,"COUNT: %d",
			COUNTER2);
			mdclog_write(MDCLOG_INFO,"Malicious: %d. I am UE 71",maliciousseventyone);
		}
		
		mdclog_write(MDCLOG_DEBUG, "COUNTER1: %d", COUNTER1);
		mdclog_write(MDCLOG_DEBUG, "COUNTER2: %d", COUNTER2);
		
		if( malicious == 1)
			{
			
			if (TOTAL_TX_1 > TOTAL_TX_2)
			{
				ue1imsi = "001010123456789";
				ue2imsi = "001010123456780";
				mdclog_write(MDCLOG_INFO,"I am inside the malicious==1 and TOTAL_TX_1 > TOTAL_TX_2");

			}

			else
			{
				ue1imsi = "001010123456780";
				ue2imsi = "001010123456789";
			

			}

			if (COUNTER1 == 10)
			{	
				float avg_tx_1=TOTAL_TX_1/10;
    				std::unique_lock<std::mutex> lock(mutex);

				mdclog_write(MDCLOG_INFO,"Avg tx_pkts UE 70 '%d': %f",
				ue_name, avg_tx_1);

				TOTAL_TX_1 = 0;
				COUNTER1 = 0;
			}	


			       if (COUNTER2 == 10)
                        {
                                float avg_tx_2=TOTAL_TX_2/10;
                                std::unique_lock<std::mutex> lock(mutex);

                                mdclog_write(MDCLOG_INFO,"Avg tx_pkts UE 71 '%d': %f",
                                ue_name, avg_tx_2);

                                TOTAL_TX_2 = 0;
                                COUNTER1 = 0;
                        }

				
			  if(malicious == 1 && ue_name ==malue)
			  {
				//if(avg_tx_1 >= tx_threshold){

					tx_threshold *= 10;
				 mdclog_write(MDCLOG_INFO,"I am inside the malicious==1 && ue_name == 70 and counter 1= 10");

					mdclog_write(MDCLOG_DEBUG, "UE1 imsi: %s", ue1imsi.c_str());
					mdclog_write(MDCLOG_DEBUG, "UE2 imsi: %s", ue2imsi.c_str());

					mdclog_write(MDCLOG_DEBUG,"UE[%d] found MALICIOUS",
					ue_name);

					AppError *ae = nullptr;

					//delete slicing binding to UE

					//need imsi and what slice the UE is bound to.

					mdclog_write(MDCLOG_DEBUG,"UNBINDING START");
					mutex.unlock();
					unbind_ue_slice(ue1imsi,slice1,&ae);
					mutex.lock();
					mdclog_write(MDCLOG_DEBUG,"UNBINDING SUCCESS");
					
					
					// Stop the timer
					auto response_end_time = std::chrono::high_resolution_clock::now();

					// Calculate the elapsed time for response
					auto response_elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(response_end_time - response_start_time);

					// Get the current date and time for logging
					std::time_t response_current_time_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

					// Log the elapsed time and current date/time for response using mdclog
					mdclog_write(MDCLOG_DEBUG, "Elapsed time (response): %ld microseconds at %s", response_elapsed_time.count(), std::ctime(&response_current_time_t));

					/*
					mutex.unlock();
					del(App::ResourceType::UeResource, ue1imsi, &ae);
					mutex.lock(); */

					/*rapidjson::Document d;
    				d.Parse(request.body().c_str());
					string writmalicious = 0;er == "imsi\":\"001010123456789\",\"tmsi\":\"\",\"crnti\":\"\",\"status\":{\"connected\":false}"
					Ue *ue = Ue::create(d,&ae); */
					
					//mutex.unlock();
					/*
					// Create a JSON object that represents the UE. 
					rapidjson::Document d; 
					d.SetObject(); 
					d.AddMember("imsi", rapidjson::Value().SetString("001010123456789"), d.GetAllocator());  */

					// Call the postUE() method. 
					//server.postUe(d, &ae);
					//add(App::ResourceType::UeResource,ue,writer,&ae);
					//mutex.lock();

                    //slice create does not have a non REST way to create slices. For now just use curl to create an initial malicious slice

					// Create a response object. 
					/*malicious = 0;

					Pistache::Http::ResponseWriter response;
					server.postUe(d, response); 
					// Check the response code. 
					if (response.status() != Pistache::Http::Code::OK) 
					{ std::cerr << "Error: " << response.status() << std::endl; return 1; } 
					// Check the response body. 
					const std::string& body = response.body(); 
					if (body != "UE created successfully.") 
					{ std::cerr << "Error: unexpected response body: " << body << std::endl; return 1; }
					
					*/

					mdclog_write(MDCLOG_DEBUG,"BINDING START");
					//bind to malicious UE to secure slice
					mutex.unlock();
					bind_ue_slice(ue1imsi,slice2,&ae);
					mutex.lock();
					mdclog_write(MDCLOG_DEBUG,"BINDING SUCCESS");
						//print something here telling us wht happened
					malicious = 0;
					maliciousseventy = 0;



				 }



/*
			   if(maliciousseventyone==1 && ue_name == 72)
			   {

                                // if(avg_tx_2 >= tx_threshold)
                                // {
                                        tx_threshold *= 10;

                                        mdclog_write(MDCLOG_DEBUG, "UE1imsi: %s", ue1imsi.c_str());
                                        mdclog_write(MDCLOG_DEBUG, "UE2 imsi: %s", ue2imsi.c_str());
                                        mdclog_write(MDCLOG_DEBUG,"UE[%d] found MALICIOUS",
                                        ue_name);
                                        //slice_name.c_str(),new_share_factors[slice_name]);

                                        AppError *ae = nullptr;

                                        //delete slicing binding to UE

                                        //need imsi and what slice the UE is bound to.
                                        mdclog_write(MDCLOG_DEBUG,"UNBINDING START");
                                        mutex.unlock();
					unbind_ue_slice(ue2imsi,slice1,&ae);
                                        mutex.lock();
                                        mdclog_write(MDCLOG_DEBUG,"UNBINDING SUCCESS");

                    //slice create does not have a non REST way to create slices. For now just use curl to create an initial malicious slice


                                        //create secure slice
                                        // string x="MALICIOUS";
                                        // d=x.c_str();
                                        // Slice *slice = Slice::create(d,&ae);


                                        mdclog_write(MDCLOG_DEBUG,"BINDING START");
                                        //bind to malicious UE to secure slice
                                        mutex.unlock();
                                        bind_ue_slice(ue2imsi,slice2,&ae);
                                        mutex.lock();
                                        mdclog_write(MDCLOG_DEBUG,"BINDING SUCCESS");
                                        malicious = 0;
					maliciousseventyone = 0;
                                        //print something here

                           

		}

		*/
		}
 }
    // Handle any updates; log either way.
    for (auto it = new_share_factors.begin(); it != new_share_factors.end(); ++it) {
	std::string slice_name = it->first;
	// Update the policies and push out control messages to bound
	// nodebs.
	Slice *slice = slices[slice_name];
	ProportionalAllocationPolicy *policy = policies[slice_name];
	int cshare = policy->getShare();
	int nshare = std::min((int)(cshare + (cshare * it->second)),1024);
	
	if (nshare < 1 || nshare < 64)
	{
	    //nshare = 1;
	    nshare = 64;
	}

	if (influxdb) {
	    influxdb->write(influxdb::Point{"share"}
		.addField("share", nshare)
		.addTag("slice", slice_name.c_str()));
	}
	policy->setShare(nshare);
	if (cshare == nshare) {
	    mdclog_write(MDCLOG_INFO,"slice '%s' share unchanged: %d",
			 slice_name.c_str(),nshare);
	    continue;
	}
	mdclog_write(MDCLOG_INFO,"slice '%s' share: %d -> %d",
		     slice_name.c_str(),cshare,nshare);
	e2sm::nexran::ProportionalAllocationPolicy *npolicy = \
	    new e2sm::nexran::ProportionalAllocationPolicy(nshare);
	e2sm::nexran::SliceConfig *sc = new e2sm::nexran::SliceConfig(slice_name,npolicy);
	e2sm::nexran::SliceConfigRequest *sreq = new e2sm::nexran::SliceConfigRequest(nexran,sc);
	sreq->encode();

	for (auto it2 = db[ResourceType::NodeBResource].begin();
	     it2 != db[ResourceType::NodeBResource].end();
	     ++it2) {
	    NodeB *nodeb = (NodeB *)it2->second;

	    if (!nodeb->is_slice_bound(slice_name))
		continue;

	    // Each request needs a different RequestId, so we have to
	    // re-encode each time.
	    std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
                e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		1,sreq,e2ap::CONTROL_REQUEST_ACK);
	    creq->set_meid(nodeb->getName());
	    e2ap.send_control_request(creq,nodeb->getName());
	}
    }

    mutex.unlock();
    return true;
}

bool App::handle(e2sm::zylinium::MaskStatusIndication *ind)
{
    mdclog_write(MDCLOG_INFO,"MaskStatusIndication: %s",
		 ind->report->to_string('\n',',').c_str());

    std::string rname;
    int total_prbs = -1;
    if (ind->parent && ind->parent->subscription_request != nullptr) {
	mutex.lock();
	rname = ind->parent->subscription_request->meid;
	if (db[ResourceType::NodeBResource].count(rname) > 0) {
	    NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][rname];
	    nodeb->update_mask_from_status(ind->report);
	    nodeb->update_last_indication();
	    total_prbs = nodeb->get_total_prbs();
	}
	mutex.unlock();
    }

    if (influxdb && total_prbs > 0) {
	int dl_masked_bits = ind->report->dl_mask.get_masked_bit_count(total_prbs);
	int ul_masked_bits = ind->report->ul_mask.get_masked_bit_count(total_prbs);
	int dl_available_bits = ind->report->dl_mask.get_available_bit_count(total_prbs);
	int ul_available_bits = ind->report->ul_mask.get_available_bit_count(total_prbs);

	influxdb->write(influxdb::Point{"masks"}
	    .addField("dl_masked_bits", (long long int)dl_masked_bits)
	    .addField("ul_masked_bits", (long long int)ul_masked_bits)
	    .addField("dl_available_bits", (long long int)dl_available_bits)
	    .addField("ul_available_bits", (long long int)ul_available_bits)
        .addTag("nodeb", rname.c_str()));
    }

    return true;
}

void App::response_handler()
{
    std::unique_lock<std::mutex> lock(mutex);

    while (!should_stop) {
	if (cv.wait_for(lock,std::chrono::seconds(1)) == std::cv_status::timeout)
	    continue;
	for (auto it = request_groups.begin(); it != request_groups.end(); ++it) {
	    int succeeded = 0,failed = 0,pending = 0;
	    RequestGroup *group = *it;
	    if (group->is_done(&succeeded,&failed,&pending)
		|| group->is_expired()) {
		std::shared_ptr<RequestContext> ctx = group->get_ctx();
		Pistache::Http::ResponseWriter& response = ctx->get_response();
		if (pending)
		    response.send(static_cast<Pistache::Http::Code>(504));
		else if (failed)
		    response.send(static_cast<Pistache::Http::Code>(502));
		else
		    response.send(static_cast<Pistache::Http::Code>(200));

		request_groups.erase(it);
	    }
	}
	lock.unlock();
	cv.notify_one();
    }
}

void App::init()
{
    db[ResourceType::SliceResource][std::string("default")] = new Slice("default");
}

void App::start()
{
    if (running)
	return;

    should_stop = false;

    /*
     * Init the E2.  Note there is nothing to do until we are configured
     * via northbound interface with objects.  Eventually we should
     * store config in the RNIB and restore things on startup, possibly.
     */
    e2ap.init();

    Add_msg_cb(RIC_SUB_RESP,rmr_callback,this);
    Add_msg_cb(RIC_SUB_FAILURE,rmr_callback,this);
    Add_msg_cb(RIC_SUB_DEL_RESP,rmr_callback,this);
    Add_msg_cb(RIC_SUB_DEL_FAILURE,rmr_callback,this);
    Add_msg_cb(RIC_CONTROL_ACK,rmr_callback,this);
    Add_msg_cb(RIC_CONTROL_FAILURE,rmr_callback,this);
    Add_msg_cb(RIC_INDICATION,rmr_callback,this);

    rmr_thread = new std::thread(&App::Listen,this);
    response_thread = new std::thread(&App::response_handler,this);

    /*
     * Init and start the northbound interface.
     * NB: the RMR Messenger superclass is already running at this point.
     */
    server.init(this);
    server.start();
    running = true;
}

void App::stop()
{
    /* Stop the northbound interface. */
    server.stop();
    /* Stop the RMR Messenger superclass. */
    Stop();
    should_stop = true;
    rmr_thread->join();
    delete rmr_thread;
    rmr_thread = NULL;
    response_thread->join();
    delete response_thread;
    response_thread = NULL;
    running = false;
}

void App::serialize(ResourceType rt,
		    rapidjson::Writer<rapidjson::StringBuffer>& writer)
{
    const char *label;

    mutex.lock();
    writer.StartObject();
    writer.String(rtype_to_label_plural[rt]);
    writer.StartArray();
    for (auto it = db[rt].begin(); it != db[rt].end(); ++it)
	it->second->serialize(writer);
    writer.EndArray();
    writer.EndObject();
    mutex.unlock();
}

bool App::serialize(ResourceType rt,std::string& rname,
		    rapidjson::Writer<rapidjson::StringBuffer>& writer,
		    AppError **ae)
{
    mutex.lock();
    if (db[rt].count(rname) < 1) {
	mutex.unlock();
	if (ae) {
	    if (*ae == NULL)
		*ae = new AppError(404);
	    (*ae)->add(std::string(rtype_to_label[rt])
		       + std::string(" does not exist"));
	}
	return false;
    }

    db[rt][rname]->serialize(writer);
    mutex.unlock();
    return true;
}

bool App::add(ResourceType rt,AbstractResource *resource,
	      rapidjson::Writer<rapidjson::StringBuffer>& writer,
	      AppError **ae)
{
    std::string& rname = resource->getName();

    mutex.lock();
    if (db[rt].count(rname) > 0) {
	if (ae) {
	    if (*ae == NULL)
		*ae = new AppError(403);
	    (*ae)->add(std::string(rtype_to_label[rt])
		       + std::string(" already exists"));
	}
	mutex.unlock();
	return false;
    }

    db[rt][rname] = resource;
    resource->serialize(writer);
    mutex.unlock();

    if (rt == App::ResourceType::NodeBResource) {
	NodeB *nodeb = (NodeB *)resource;

	/*
	e2sm::nexran::EventTrigger *trigger = \
	    new e2sm::nexran::EventTrigger(nexran,1000);
	std::list<e2ap::Action *> actions;
	actions.push_back(new e2ap::Action(1,e2ap::ACTION_REPORT,NULL,-1));
	std::shared_ptr<e2ap::SubscriptionRequest> req = \
	    std::make_shared<e2ap::SubscriptionRequest>(
		e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		1,trigger,actions);
	req->set_meid(rname);
	e2ap.send_subscription_request(req,rname);
	*/

	e2sm::nexran::SliceStatusRequest *sreq = \
	    new e2sm::nexran::SliceStatusRequest(nexran);
	std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
            e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	    1,sreq,e2ap::CONTROL_REQUEST_ACK);
	creq->set_meid(rname);
	e2ap.send_control_request(creq,rname);

	e2sm::kpm::EventTrigger *trigger = \
	    new e2sm::kpm::EventTrigger(kpm,app_config.kpm_interval_index);
	std::list<e2ap::Action *> actions;
	actions.push_back(new e2ap::Action(1,e2ap::ACTION_REPORT,NULL,-1));
	std::shared_ptr<e2ap::SubscriptionRequest> req = \
	    std::make_shared<e2ap::SubscriptionRequest>(
		e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		0,trigger,actions);
	req->set_meid(rname);
	e2ap.send_subscription_request(req,rname);

	e2sm::zylinium::MaskStatusRequest *msreq = \
	    new e2sm::zylinium::MaskStatusRequest(zylinium);
	std::shared_ptr<e2ap::ControlRequest> mscreq = std::make_shared<e2ap::ControlRequest>(
            e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	    2,msreq,e2ap::CONTROL_REQUEST_ACK);
	mscreq->set_meid(rname);
	e2ap.send_control_request(mscreq,rname);

	e2sm::zylinium::EventTrigger *ztrigger = \
	    new e2sm::zylinium::EventTrigger(zylinium);
	std::list<e2ap::Action *> zactions;
	zactions.push_back(new e2ap::Action(1,e2ap::ACTION_REPORT,NULL,-1));
	std::shared_ptr<e2ap::SubscriptionRequest> zreq = \
	    std::make_shared<e2ap::SubscriptionRequest>(
		e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		2,ztrigger,zactions);
	zreq->set_meid(rname);
	e2ap.send_subscription_request(zreq,rname);

	e2sm::zylinium::MaskConfigRequest *mcreq = \
	    nodeb->make_mask_config_request(zylinium);
	std::shared_ptr<e2ap::ControlRequest> mccreq = std::make_shared<e2ap::ControlRequest>(
            e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	    2,mcreq,e2ap::CONTROL_REQUEST_ACK);
	mccreq->set_meid(rname);
	e2ap.send_control_request(mccreq,rname);
    }

    mdclog_write(MDCLOG_DEBUG,"added %s %s",
		 rtype_to_label[rt],resource->getName().c_str());

    return true;
}

bool App::del(ResourceType rt,std::string& rname,
	      AppError **ae)
{
    mutex.lock();
    if (db[rt].count(rname) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("not found"));
	}
	return false;
    }

    mdclog_write(MDCLOG_DEBUG,"deleting %s %s",
		 rtype_to_label[rt],rname.c_str());

    if (rt == App::ResourceType::UeResource) {
	Ue *ue = (Ue *)db[App::ResourceType::UeResource][rname];
	std::string &imsi = ue->getName();

	if (ue->is_bound()
	    && db[App::ResourceType::SliceResource].count(ue->get_bound_slice()) > 0) {
	    std::string &slice_name = ue->get_bound_slice();
	    Slice *slice = (Slice *)db[App::ResourceType::SliceResource][slice_name];

	    if (!slice->unbind_ue(imsi)) {
		mutex.unlock();
		if (ae) {
		    if (!*ae)
			*ae = new AppError(404);
		    (*ae)->add(std::string("ue not bound to this slice"));
		}
		return false;
	    }

	    e2sm::nexran::SliceUeUnbindRequest *sreq = \
		new e2sm::nexran::SliceUeUnbindRequest(nexran,slice_name,imsi);

	    for (auto it = db[ResourceType::NodeBResource].begin();
		 it != db[ResourceType::NodeBResource].end();
		 ++it) {
		NodeB *nodeb = (NodeB *)it->second;

		if (!nodeb->is_slice_bound(slice_name))
		    continue;

		// Each request needs a different RequestId, so we have to
		// re-encode each time.
		std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
                    e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		    1,sreq,e2ap::CONTROL_REQUEST_ACK);
		creq->set_meid(nodeb->getName());
		e2ap.send_control_request(creq,nodeb->getName());
	    }
	}
    }
    else if (rt == App::ResourceType::SliceResource) {
	Slice *slice = (Slice *)db[App::ResourceType::SliceResource][rname];

        e2sm::nexran::SliceDeleteRequest *sreq = \
	    new e2sm::nexran::SliceDeleteRequest(nexran,rname);

	for (auto it = db[ResourceType::NodeBResource].begin();
	     it != db[ResourceType::NodeBResource].end();
	     ++it) {
	    NodeB *nodeb = (NodeB *)it->second;

	    if (!nodeb->is_slice_bound(rname))
		continue;

	    // Each request needs a different RequestId, so we have to
	    // re-encode each time.
	    std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
                e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		1,sreq,e2ap::CONTROL_REQUEST_ACK);
	    creq->set_meid(nodeb->getName());
	    e2ap.send_control_request(creq,nodeb->getName());
	}

	slice->unbind_all_ues();
    }
    else if (rt == App::ResourceType::NodeBResource) {
	NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][rname];
	std::map<std::string,Slice *>& slices = nodeb->get_slices();

	if (!slices.empty()) {
	    std::list<std::string> deletes;
	    for (auto it = slices.begin(); it != slices.end(); ++it)
		deletes.push_back(it->first);

	    e2sm::nexran::SliceDeleteRequest *sreq = \
		new e2sm::nexran::SliceDeleteRequest(nexran,deletes);

	    std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
                e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		1,sreq,e2ap::CONTROL_REQUEST_ACK);
	    creq->set_meid(nodeb->getName());
	    e2ap.send_control_request(creq,nodeb->getName());
	}

	e2ap.delete_all_subscriptions(rname);
    }

    delete db[rt][rname];
    db[rt].erase(rname);

    mutex.unlock();

    return true;
}

bool App::update(ResourceType rt,std::string& rname,
		 rapidjson::Document& d,
		 AppError **ae)
{
    mutex.lock();
    if (db[rt].count(rname) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("not found"));
	}
	return false;
    }

    if (!db[rt][rname]->update(d,ae)) {
	mutex.unlock();
	return false;
    }

    if (rt == App::ResourceType::NodeBResource) {
	NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][rname];

	e2sm::zylinium::MaskConfigRequest *mreq = \
	    nodeb->make_mask_config_request(zylinium);
	std::shared_ptr<e2ap::ControlRequest> creq = \
	    std::make_shared<e2ap::ControlRequest>(
            e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	    2,mreq,e2ap::CONTROL_REQUEST_ACK);
	creq->set_meid(rname);
	e2ap.send_control_request(creq,rname);
    }
    else if (rt == App::ResourceType::SliceResource) {
	Slice *slice = (Slice *)db[App::ResourceType::SliceResource][rname];

	ProportionalAllocationPolicy *policy = dynamic_cast<ProportionalAllocationPolicy *>(slice->getPolicy());
	e2sm::nexran::ProportionalAllocationPolicy *npolicy = \
	    new e2sm::nexran::ProportionalAllocationPolicy(policy->getShare());
	e2sm::nexran::SliceConfig *sc = new e2sm::nexran::SliceConfig(slice->getName(),npolicy);
	e2sm::nexran::SliceConfigRequest *sreq = new e2sm::nexran::SliceConfigRequest(nexran,sc);
	sreq->encode();

	for (auto it = db[ResourceType::NodeBResource].begin();
	     it != db[ResourceType::NodeBResource].end();
	     ++it) {
	    NodeB *nodeb = (NodeB *)it->second;

	    if (!nodeb->is_slice_bound(rname))
		continue;

	    // Each request needs a different RequestId, so we have to
	    // re-encode each time.
	    std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
                e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
		1,sreq,e2ap::CONTROL_REQUEST_ACK);
	    creq->set_meid(nodeb->getName());
	    e2ap.send_control_request(creq,nodeb->getName());
	}
    }

    mutex.unlock();

    mdclog_write(MDCLOG_DEBUG,"updated %s %s",
		 rtype_to_label[rt],rname.c_str());

    return true;
}

bool App::bind_slice_nodeb(std::string& slice_name,std::string& nodeb_name,
			   AppError **ae)
{
    mutex.lock();
    if (db[App::ResourceType::SliceResource].count(slice_name) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("slice does not exist"));
	}
	return false;
    }
    if (db[App::ResourceType::NodeBResource].count(nodeb_name) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("nodeb does not exist"));
	}
	return false;
    }
    Slice *slice = (Slice *)db[App::ResourceType::SliceResource][slice_name];
    NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][nodeb_name];
	
    if (!nodeb->bind_slice(slice)) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(403);
	    (*ae)->add(std::string("slice already bound to nodeb"));
	}
	return false;
    }

    ProportionalAllocationPolicy *policy = dynamic_cast<ProportionalAllocationPolicy *>(slice->getPolicy());
    e2sm::nexran::ProportionalAllocationPolicy *npolicy = \
	new e2sm::nexran::ProportionalAllocationPolicy(policy->getShare());
    e2sm::nexran::SliceConfig *sc = new e2sm::nexran::SliceConfig(slice->getName(),npolicy);
    e2sm::nexran::SliceConfigRequest *sreq = new e2sm::nexran::SliceConfigRequest(nexran,sc);
    std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
        e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	1,sreq,e2ap::CONTROL_REQUEST_ACK);
    creq->set_meid(nodeb->getName());
    e2ap.send_control_request(creq,nodeb->getName());

    mutex.unlock();

    mdclog_write(MDCLOG_DEBUG,"bound slice %s to nodeb %s",
		 slice_name.c_str(),nodeb->getName().c_str());

    return true;
}

bool App::unbind_slice_nodeb(std::string& slice_name,std::string& nodeb_name,
			     AppError **ae)
{
    mutex.lock();
    if (db[App::ResourceType::SliceResource].count(slice_name) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("slice does not exist"));
	}
	return false;
    }
    if (db[App::ResourceType::NodeBResource].count(nodeb_name) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("nodeb does not exist"));
	}
	return false;
    }
    NodeB *nodeb = (NodeB *)db[App::ResourceType::NodeBResource][nodeb_name];
	
    if (!nodeb->unbind_slice(slice_name)) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("slice not bound to this nodeb"));
	}
	return false;
    }

    e2sm::nexran::SliceDeleteRequest *sreq = \
	new e2sm::nexran::SliceDeleteRequest(nexran,slice_name);
    std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
        e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	1,sreq,e2ap::CONTROL_REQUEST_ACK);
    creq->set_meid(nodeb->getName());
    e2ap.send_control_request(creq,nodeb->getName());

    mutex.unlock();

    mdclog_write(MDCLOG_DEBUG,"unbound slice %s from nodeb %s",
		 slice_name.c_str(),nodeb->getName().c_str());

    return true;
}

bool App::bind_ue_slice(std::string& imsi,std::string& slice_name,
			AppError **ae)
{
    mutex.lock();

    if (db[App::ResourceType::SliceResource].count(slice_name) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("slice does not exist"));
	}
	return false;
    }

    if (db[App::ResourceType::UeResource].count(imsi) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("ue does not exist"));
	}
	return false;
    }

    Ue *ue = (Ue *)db[App::ResourceType::UeResource][imsi];
    Slice *slice = (Slice *)db[App::ResourceType::SliceResource][slice_name];

	//ue->bind_slice(slice_name);


    if (ue->is_bound() || !slice->bind_ue(ue)) {
		if (ue->is_bound()){mdclog_write(MDCLOG_DEBUG,"first condition");}
		if (!slice->bind_ue(ue)) {mdclog_write(MDCLOG_DEBUG,"second condition");}
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(403);
	    (*ae)->add(std::string("ue already bound to slice"));
	}
	return false;
    }

    ue->bind_slice(slice_name);

    e2sm::nexran::SliceUeBindRequest *sreq = \
	new e2sm::nexran::SliceUeBindRequest(nexran,slice->getName(),ue->getName());

    for (auto it = db[ResourceType::NodeBResource].begin();
	 it != db[ResourceType::NodeBResource].end();
	 ++it) {
	NodeB *nodeb = (NodeB *)it->second;

	if (!nodeb->is_slice_bound(slice_name))
	    continue;

	// Each request needs a different RequestId, so we have to
	// re-encode each time.

	std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
            e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	    1,sreq,e2ap::CONTROL_REQUEST_ACK);
	creq->set_meid(nodeb->getName());
	e2ap.send_control_request(creq,nodeb->getName());
    }

    mutex.unlock();

    mdclog_write(MDCLOG_DEBUG,"bound ue %s to slice %s",
		 imsi.c_str(),slice_name.c_str());

    return true;
}

bool App::unbind_ue_slice(std::string& imsi,std::string& slice_name,
			  AppError **ae)
{
	mutex.lock();

	//creating ue to add one extra lien of code later -----> ue->unbind_slice();
	Ue *ue = (Ue *)db[App::ResourceType::UeResource][imsi];

    if (db[App::ResourceType::SliceResource].count(slice_name) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("slice does not exist"));

	}
	return false;
    }

    if (db[App::ResourceType::UeResource].count(imsi) < 1) {
	mutex.unlock();
	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("ue does not exist"));
	}
	return false;
    }
    Slice *slice = (Slice *)db[App::ResourceType::SliceResource][slice_name];

    if (!slice->unbind_ue(imsi)) {
	mutex.unlock();

	if (ae) {
	    if (!*ae)
		*ae = new AppError(404);
	    (*ae)->add(std::string("ue not bound to this slice"));
	}
	return false;
    }

    e2sm::nexran::SliceUeUnbindRequest *sreq = \
	new e2sm::nexran::SliceUeUnbindRequest(nexran,slice->getName(),imsi);

    for (auto it = db[ResourceType::NodeBResource].begin();
	 it != db[ResourceType::NodeBResource].end();
	 ++it) {
	NodeB *nodeb = (NodeB *)it->second;

	if (!nodeb->is_slice_bound(slice_name))
	    continue;

	// Each request needs a different RequestId, so we have to
	// re-encode each time.
	std::shared_ptr<e2ap::ControlRequest> creq = std::make_shared<e2ap::ControlRequest>(
            e2ap.get_requestor_id(),e2ap.get_next_instance_id(),
	    1,sreq,e2ap::CONTROL_REQUEST_ACK);
	creq->set_meid(nodeb->getName());
	e2ap.send_control_request(creq,nodeb->getName());
    }

	//added this while modifying the code for intrusion detection
	ue->unbind_slice();

    mutex.unlock();
    mdclog_write(MDCLOG_DEBUG,"unbound ue %s from slice %s",
		 imsi.c_str(),slice_name.c_str());

    return true;
}

bool App::handle_appconfig_update(void)
{
    if (app_config.influxdb_url != influxdb_url) {
	if (influxdb)
	    influxdb.reset(nullptr);
	if (app_config.influxdb_url.length() > 0) {
	    influxdb = influxdb::InfluxDBFactory::Get(app_config.influxdb_url.c_str());
	    influxdb_url = app_config.influxdb_url;
	}
	else {
	    influxdb_url = std::string();
	}
    }

    return true;
}

}
