/*
 *  Copyright (C) 2020 Palo Alto Networks Intellectual Property. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



/**
* \ingroup serverlibrary
*
* \brief gRPC Server implementation
*
*/

extern "C" {
#include "opof.h"
#include "opof_error.h"
#include "opof_serverlib.h"
}

#include "opof_util.h"
#include "opof_grpc.h"
#include "opof_session_server.h"

#include <google/protobuf/text_format.h>

#include <syslog.h>

std::ofstream opof_debug_out;

extern "C"
void opof_enable_protobuf_debugging(const char *filename)
{
  opof_debug_out.open(filename, std::ios_base::trunc);

  if (!opof_debug_out) {
    syslog(LOG_ERR, "Failed to open protobuf debug file: %s", filename);
  }
}

void opof_log_protobuf(const char *calling_func, 
  const char *inout,
  const google::protobuf::Message *msg)
{
  if (!opof_debug_out || !calling_func || !msg)
    return;
  
  opof_debug_out 
    << calling_func << " " << inout << ":" << std::endl
    << msg->DebugString() << std::endl;
}

void opof_log_int(const char *calling_func, 
  const char *inout,
  int n)
{
  if (!opof_debug_out || !calling_func)
    return;
  
  opof_debug_out 
    << calling_func << " " << inout << ":" << std::endl
    << n << std::endl;
}

Status SessionTableImpl::getServiceVersion(ServerContext* context, const versionRequest* request, versionResponse* response) {
  static constexpr size_t STR_BUFFER_LENGTH = 512;

  opof_log_protobuf(__func__, "input", request);

  char vendor[STR_BUFFER_LENGTH];
  char name[STR_BUFFER_LENGTH];
  char version[STR_BUFFER_LENGTH];
  char copyright[STR_BUFFER_LENGTH];
  int status = opof_get_version(
    vendor, STR_BUFFER_LENGTH,
    name, STR_BUFFER_LENGTH,
    version, STR_BUFFER_LENGTH,
    copyright, STR_BUFFER_LENGTH);
  
  if (status) {
    return Status::CANCELLED;
  }
  
  response->set_vendor(vendor);
  response->set_name(name);
  response->set_version(version);
  response->set_copyright(copyright);

  opof_log_protobuf(__func__, "output", response);

  return Status::OK;
}

Status SessionTableImpl::reset(ServerContext* context, const resetRequest *request, sessionResponse *response)
{
  opof_reset_server();
  return Status::OK;
}

/** \ingroup serverlibrary
* \brief addSession
*
* \param context
* \param reader
* \param response
*/
Status SessionTableImpl::addSession(ServerContext* context, ServerReader<sessionRequest>* reader, addSessionResponse* response) {
  //int index=0;
  //ADD_SESSION_STATUS reqStatus = ADD_SESSION_STATUS::_SESSION_ACCEPTED;
  sessionRequest request;
  response->clear_responseerror();
  //std::cout << "response size: " << response->responseerror_size() << std::endl;
  //if (context->IsCancelled()) {
  //  return Status(StatusCode::CANCELLED, "Deadline exceeded or Client cancelled, abandoning.");
  //}
#ifdef TESTS
  sleep(1);
#endif
  while(reader->Read(&request)){
    opof_log_protobuf(__func__, "input", &request);

    sessionRequest_t request_c = {};
    convertSessionRequest2c(request, &request_c);
    if (context->IsCancelled()) {
      return Status(StatusCode::CANCELLED, "Deadline exceeded or Client cancelled, abandoning.");
    }
    addSessionResponse_t addResponse_c = {};
    int status = opof_add_session_server(&request_c, &addResponse_c);
    if (status != _OK){
      sessionResponseError *errorMessage = response->add_responseerror();
      errorMessage->set_sessionid(request.sessionid());
      errorMessage->set_errorstatus(status);
    }
    //index++;
  }
  opof_log_protobuf(__func__, "output", response);
  //response->set_requeststatus(reqStatus);
  return Status::OK;
}

/** \ingroup serverlibrary
* \brief getSession
*
* \param context
* \param reader
* \param response
*/
Status SessionTableImpl::getSession(ServerContext* context, const sessionId* sid,
  sessionResponse* response) {
  opof_log_protobuf(__func__, "input", sid);
  sessionResponse_t response_c;
  int status;
  uint64_t session;
  if (context->IsCancelled()) {
      return Status(StatusCode::CANCELLED, "Deadline exceeded or Client cancelled, abandoning.");
  }
  session = sid->sessionid();
  status = opof_get_session_server(session, &response_c);
  opof_log_int(__func__, "output", status);
  if (status == _OK){
    convertSessionResponse2cpp(response, &response_c);
    opof_log_protobuf(__func__, "output", response);
    return Status::OK;
  } else if (status == _NOT_FOUND){
    return Status(grpc::StatusCode::NOT_FOUND, "Get Session Not Found");
  } else {
    return Status(grpc::StatusCode::UNKNOWN, "Internal Open Offload Server Error");
  }
}

/** \ingroup serverlibrary
* \brief deleteSession
*
* \param context
* \param reader
* \param response
*/
Status SessionTableImpl::deleteSession(ServerContext* context, const sessionId* sid,
  sessionResponse* response) {
  opof_log_protobuf(__func__, "input", sid);
  int status;
  sessionResponse_t response_c;
  if (context->IsCancelled()) {
    return Status(StatusCode::CANCELLED, "Deadline exceeded or Client cancelled, abandoning.");
  }
  status = opof_del_session_server(sid->sessionid(), &response_c);
  opof_log_int(__func__, "output", status);
  if (status == _OK){
    convertSessionResponse2cpp(response, &response_c);
    opof_log_protobuf(__func__, "output", response);
    return Status::OK;
  } else if (status == _NOT_FOUND){
    return Status(grpc::StatusCode::NOT_FOUND, "Delete Session Not Found");
  } else {
    return Status(grpc::StatusCode::UNKNOWN, "Internal Open Offload Server Error");
  }
}

/** \ingroup serverlibrary
* \brief getAllSessions
*
* \param context
* \param reader
* \param response
*/
Status SessionTableImpl::getAllSessions(ServerContext* context, const sessionRequestArgs* request, sessionResponses *responses) {
  opof_log_protobuf(__func__, "input", request);
  
  Status status;
  sessionResponse_t **allSessions= NULL;
  sessionResponse_t *closedResponse;
  sessionResponse *response;
  int sessionCount;
  int pageCount = 0;
  
  int nresponses = BUFFER_MAX;
  uint64_t start_session;
  if (context->IsCancelled()) {
      return Status(StatusCode::CANCELLED, "Deadline exceeded or Client cancelled, abandoning.");
  }
  start_session = request->startsession();
  
  allSessions = (sessionResponse_t **)malloc(nresponses * sizeof(sessionResponse_t *));
  for (int i = 0; i < nresponses; i++){
    allSessions[i] = (sessionResponse_t *)malloc(sizeof(sessionResponse_t));
  }
  
  sessionCount = opof_get_all_sessions_server(nresponses, &start_session, pageCount, allSessions);

  responses->set_nextkey(start_session);
  
  if (sessionCount > 0){
    pageCount++;
    for (int i=0; i < sessionCount; i++){
      closedResponse = allSessions[i];
      response = responses->add_sessioninfo();
      response->set_sessionid(closedResponse->sessionId);
      response->set_sessionstate((SESSION_STATE)closedResponse->sessionState);
      response->set_inpackets(closedResponse->inPackets);
      response->set_outpackets(closedResponse->outPackets);
      response->set_inbytes(closedResponse->inBytes);
      response->set_outbytes(closedResponse->outBytes);
      response->set_sessionclosecode((SESSION_CLOSE_CODE)closedResponse->sessionCloseCode);
      response->set_requeststatus((REQUEST_STATUS)closedResponse->requestStatus);
    }
  }
  for (int i=0; i <nresponses; i++){
    free(allSessions[i]);
  }
  free(allSessions);
  opof_log_protobuf(__func__, "output", responses);
  return Status::OK;
}

/** \ingroup serverlibrary
* \brief getClosedSessions
*
* \param context
* \param reader
* \param response
*/
Status SessionTableImpl::getClosedSessions(ServerContext* context, const sessionRequestArgs* request, ServerWriter<sessionResponse>* writer) {
  opof_log_protobuf(__func__, "input", request);
  
  sessionResponse response;
  sessionResponse_t closedResponse;
  statisticsRequestArgs_t request_c;
  int sessionCount = 0;
  //Status status;
  if (context->IsCancelled()) {
      return Status(StatusCode::CANCELLED, "Deadline exceeded or Client cancelled, abandoning.");
  }
  int nresponses = request->pagesize();
  request_c.pageSize = nresponses;
  sessionResponse_t closedSessions[BUFFER_MAX];
#ifdef TESTS
  sleep(1);
#endif
  sessionCount = opof_get_closed_sessions_server(&request_c, closedSessions);
  if (sessionCount == 0){
    return Status(grpc::StatusCode::NOT_FOUND,"No Closed Sessions");
  }
  for (int i=0; i < sessionCount; i++){
    closedResponse = closedSessions[i];
    response.set_sessionid(closedResponse.sessionId);
    response.set_sessionstate((SESSION_STATE)closedResponse.sessionState);
    response.set_inpackets(closedResponse.inPackets);
    response.set_outpackets(closedResponse.outPackets);
    response.set_inbytes(closedResponse.inBytes);
    response.set_outbytes(closedResponse.outBytes);
    response.set_sessionclosecode((SESSION_CLOSE_CODE)closedResponse.sessionCloseCode);
    response.set_requeststatus(REQUEST_STATUS::_ACCEPTED);
    opof_log_protobuf(__func__, "output", &response);
    writer->Write(response);
    
  }
  
  return Status::OK;
}

Status SessionTableImpl::addVlanFlow(ServerContext* context, const vlanFlowDef* request, sessionResponse* response) {
  opof_log_protobuf(__func__, "input", request);
  int status = opof_add_vlan_flow_server(request->vlanid(), request->internallif());
  response->set_requeststatus(status == 0 ? REQUEST_STATUS::_ACCEPTED : REQUEST_STATUS::_REJECTED);
  opof_log_protobuf(__func__, "output", response);
  return Status::OK;
}

Status SessionTableImpl::removeVlanFlow(ServerContext* context, const vlanFlowDef* request, sessionResponse* response)
{
  opof_log_protobuf(__func__, "input", request);
  int status = opof_remove_vlan_flow_server(request->vlanid());
  response->set_requeststatus(status == 0 ? REQUEST_STATUS::_ACCEPTED : REQUEST_STATUS::_REJECTED);
  opof_log_protobuf(__func__, "output", response);
  return Status::OK;
}

Status SessionTableImpl::getVlanFlows(ServerContext* context, const vlanFlowListRequest* request, vlanFlowList* response) {
  opof_log_protobuf(__func__, "input", request);
  size_t nVlanFlows = opof_get_vlan_flow_count_server();
  size_t nVlanFlowsReturned = 0;
  std::vector<uint16_t> vlanIDs(nVlanFlows);
  std::vector<uint16_t> vfIndices(nVlanFlows);
  int status = opof_get_vlan_flows_server(vlanIDs.data(), vfIndices.data(), nVlanFlows, &nVlanFlowsReturned);
  if (status == 0) {
      for (size_t i=0; i<nVlanFlowsReturned; i++) {
      auto * flowDef = response->add_flowdefs();
      flowDef->set_vlanid(vlanIDs[i]);
      flowDef->set_internallif(vfIndices[i]);
    }
  }
  opof_log_protobuf(__func__, "output", response);
  return Status::OK;
}

Status SessionTableImpl::clearVlanFlows(ServerContext* context, const vlanFlowListRequest* request, sessionResponse* response) {
  opof_log_protobuf(__func__, "input", request);
  opof_clear_vlan_flows_server();
  response->set_requeststatus(REQUEST_STATUS::_ACCEPTED);
  opof_log_protobuf(__func__, "output", response);
  return Status::OK;
}

Status SessionTableImpl::setNextHop(
  ServerContext* context, 
  const nextHopParameters *nextHop, 
  struct nextHopResponse *response)
{
  struct nextHopParameters_t nextHop_c = {};
  convertNextHop2c(nextHop, &nextHop_c);
  int status = opof_set_next_hop_server(&nextHop_c);
  response->set_errorstatus(status == 0 ? REQUEST_STATUS::_ACCEPTED : REQUEST_STATUS::_REJECTED);

  return Status::OK;
}

Status SessionTableImpl::destroyNextHop(
  ServerContext* context, 
  const nextHopParameters *nextHop, 
  struct nextHopResponse *response)
{
  int status = opof_destroy_next_hop_server(nextHop->nexthopid());
  response->set_errorstatus(status == 0 ? REQUEST_STATUS::_ACCEPTED : REQUEST_STATUS::_REJECTED);

  return Status::OK;
}

Status SessionTableImpl::clearNextHops(
  ServerContext* context, 
  const nextHopParameters *ignored, 
  struct nextHopResponse *response)
{
  int status = opof_clear_next_hops_server();
  response->set_errorstatus(status == 0 ? REQUEST_STATUS::_ACCEPTED : REQUEST_STATUS::_REJECTED);

  return Status::OK;
}
