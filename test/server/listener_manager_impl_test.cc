#include "server/listener_manager_impl.h"

#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"

#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;

namespace Envoy {
namespace Server {

class MockListenSocketFactory : public ListenSocketFactory {
public:
  Network::ListenSocketPtr create(Network::Address::InstanceConstSharedPtr address,
                                  bool bind_to_port) override {
    return Network::ListenSocketPtr{create_(address, bind_to_port)};
  }

  MOCK_METHOD2(create_, Network::ListenSocket*(Network::Address::InstanceConstSharedPtr address,
                                               bool bind_to_port));
};

class ListenerManagerImplTest : public testing::Test {
public:
  NiceMock<MockInstance> server_;
  MockListenSocketFactory factory_;
  ListenerManagerImpl manager_{server_, factory_};
};

TEST_F(ListenerManagerImplTest, EmptyFilter) {
  std::string json = R"EOF(
  {
    "address": "tcp://127.0.0.1:1234",
    "filters": []
  }
  )EOF";

  Json::ObjectSharedPtr loader = Json::Factory::loadFromString(json);
  EXPECT_CALL(factory_, create_(_, true));
  manager_.addListener(*loader);
  EXPECT_EQ(1U, manager_.listeners().size());
}

TEST_F(ListenerManagerImplTest, DefaultListenerPerConnectionBufferLimit) {
  std::string json = R"EOF(
  {
    "address": "tcp://127.0.0.1:1234",
    "filters": []
  }
  )EOF";

  Json::ObjectSharedPtr loader = Json::Factory::loadFromString(json);
  EXPECT_CALL(factory_, create_(_, true));
  manager_.addListener(*loader);
  EXPECT_EQ(1024 * 1024U, manager_.listeners().back().get().perConnectionBufferLimitBytes());
}

TEST_F(ListenerManagerImplTest, SetListenerPerConnectionBufferLimit) {
  std::string json = R"EOF(
  {
    "address": "tcp://127.0.0.1:1234",
    "filters": [],
    "per_connection_buffer_limit_bytes": 8192
  }
  )EOF";

  Json::ObjectSharedPtr loader = Json::Factory::loadFromString(json);
  EXPECT_CALL(factory_, create_(_, true));
  manager_.addListener(*loader);
  EXPECT_EQ(8192U, manager_.listeners().back().get().perConnectionBufferLimitBytes());
}

TEST_F(ListenerManagerImplTest, SslContext) {
  std::string json = R"EOF(
  {
    "address": "tcp://127.0.0.1:1234",
    "filters" : [],
    "ssl_context" : {
      "cert_chain_file" : "{{ test_rundir }}/test/common/ssl/test_data/san_uri_cert.pem",
      "private_key_file" : "{{ test_rundir }}/test/common/ssl/test_data/san_uri_key.pem",
      "verify_subject_alt_name" : [
        "localhost",
        "127.0.0.1"
      ]
    }
  }
  )EOF";

  Json::ObjectSharedPtr loader = TestEnvironment::jsonLoadFromString(json);
  EXPECT_CALL(factory_, create_(_, true));
  manager_.addListener(*loader);
  EXPECT_NE(nullptr, manager_.listeners().back().get().sslContext());
}

} // Server
} // Envoy
