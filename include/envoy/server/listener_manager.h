#pragma once

#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"
#include "envoy/ssl/context.h"

namespace Envoy {
namespace Server {

/**
 * A configuration for an individual listener.
 */
class Listener {
public:
  virtual ~Listener() {}

  /**
   * @return Network::FilterChainFactory& the factory for setting up the filter chain on a new
   *         connection.
   */
  virtual Network::FilterChainFactory& filterChainFactory() PURE;

  /**
   * @return Network::Address::InstanceConstSharedPtr the address. fixfix
   */
  virtual Network::Address::InstanceConstSharedPtr address() PURE;

  /**
   * fixfix
   */
  virtual Network::ListenSocket& socket() PURE;

  /**
   * @return Ssl::ServerContext* the SSL context
   */
  virtual Ssl::ServerContext* sslContext() PURE;

  /**
   * @return bool whether to use the PROXY Protocol V1
   * (http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt)
   */
  virtual bool useProxyProto() PURE;

  /**
   * @return bool specifies whether the listener should actually listen on the port.
   *         A listener that doesn't listen on a port can only receive connections
   *         redirected from other listeners.
   */
  virtual bool bindToPort() PURE;

  /**
   * @return bool if a connection was redirected to this listener address using iptables,
   *         allow the listener to hand it off to the listener associated to the original address
   */
  virtual bool useOriginalDst() PURE;

  /**
   * @return uint32_t providing a soft limit on size of the listener's new connection read and write
   *         buffers.
   */
  virtual uint32_t perConnectionBufferLimitBytes() PURE;

  /**
   * @return Stats::Scope& the stats scope to use for all listener specific stats.
   */
  virtual Stats::Scope& listenerScope() PURE;
};

typedef std::unique_ptr<Listener> ListenerPtr;

/**
 * fixfix all
 */
class ListenerManager {
public:
  virtual ~ListenerManager() {}

  /**
   * fixfix
   */
  virtual void addListener(const Json::Object& json) PURE;

  /**
   * fixfix
   */
  virtual std::list<std::reference_wrapper<Listener>> listeners() PURE;
};

} // Server
} // Envoy
