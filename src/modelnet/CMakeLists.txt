# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(NOT WITH_MODELNET)
  return()
endif()

find_package(OpenSSL REQUIRED)

add_library(bitcoin_modelnet STATIC
  types.cpp
  crypto.cpp
  resource_uri.cpp
  records.cpp
  policy.cpp
  protocol.cpp
  store.cpp
  swarm.cpp
  router.cpp
  transport_pq.cpp
  bridge.cpp
  transfer.cpp
  release.cpp
  qualification.cpp
  identity.cpp
  acl.cpp
  http_bridge.cpp
)
target_link_libraries(bitcoin_modelnet
  PUBLIC
    core_interface
    bitcoin_crypto
    bitcoin_util
    bitcoin_common
    univalue
    bitcoinpqc
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_include_directories(bitcoin_modelnet
  PUBLIC
    ${PROJECT_SOURCE_DIR}/src
)

add_executable(btx-modeld ../modeld.cpp)
set_target_properties(btx-modeld PROPERTIES OUTPUT_NAME btx-modeld)
target_link_libraries(btx-modeld core_interface)
if(UNIX AND NOT APPLE)
  target_link_btx_linux_archive_group(btx-modeld bitcoin_modelnet ${BTX_BASE_ARCHIVES})
else()
  target_link_libraries(btx-modeld bitcoin_modelnet)
endif()

add_executable(btx-modelcheck ../modelcheck.cpp)
set_target_properties(btx-modelcheck PROPERTIES OUTPUT_NAME btx-modelcheck)
target_link_libraries(btx-modelcheck core_interface)
if(UNIX AND NOT APPLE)
  target_link_btx_linux_archive_group(btx-modelcheck bitcoin_modelnet ${BTX_BASE_ARCHIVES})
else()
  target_link_libraries(btx-modelcheck bitcoin_modelnet)
endif()

install(TARGETS btx-modeld btx-modelcheck RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
