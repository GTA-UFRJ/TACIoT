#include "/home/guiaraujo/cpp-httplib/httplib.h"
#include <string.h>
#include <iostream>
#include <stdio.h>

const uint8_t client_data[99] = {0xdd, 0xb1, 0xb6, 0xb8, 0x22, 0xd3, 0x9a, 0x76, 0x1c, 
                                 0xb6, 0xc0, 0x30, 0x6a, 0xe9, 0x21, 0x5a, 0x00, 0x00, 
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                 0x00, 0x73, 0xe3, 0xa6, 0xf9, 0x52, 0xd2, 0x97, 0xa3, 
                                 0xc1, 0x10, 0xf3, 0xc5, 0x05, 0xcb, 0x8e, 0x1d, 0x8b, 
                                 0xe2, 0xcf, 0xcc, 0x16, 0x26, 0x2c, 0x4f, 0x83, 0x94, 
                                 0xe4, 0x9a, 0xe0, 0xee, 0xb3, 0x9c, 0x50, 0x63, 0x68, 
                                 0x4d, 0x21, 0x12, 0xf0, 0xa6, 0x12, 0xbc, 0x86, 0x9d, 
                                 0xe1, 0xa3, 0x9b, 0xd9, 0xf9, 0x31, 0xd2, 0x7c, 0x63, 
                                 0xe3, 0x40, 0x0e, 0x08, 0x17, 0xd3, 0xd2, 0xf8, 0xbf, 
                                 0xbf, 0xc0, 0xee, 0xea, 0x4c, 0xb7, 0x90, 0xdf, 0x00};

int main(void)
{
  using namespace httplib;

  Server svr;

  svr.Get("/hia", [](const Request& req, Response& res) {
    int dumb;
    res.set_content("Hello !", "text/plain");
  });

  svr.Get(R"(/numbers/(\d+))", [&](const Request& req, Response& res) {
    auto numbers = req.matches[1];
    res.set_content(numbers, "text/plain");
  });

  svr.Get("/body-header-param", [](const Request& req, Response& res) {
    if (req.has_header("Content-Length")) {
      auto val = req.get_header_value("Content-Length");
    }
    if (req.has_param("key")) {
      auto val = req.get_param_value("key");
    }
    res.set_content(req.body, "text/plain");
  });

  svr.Get("/stop", [&](const Request& req, Response& res) {
    svr.stop();
  });

  svr.Get(R"(/attest/type=([0-9a-f]+)&size=([0-9a-f]+)&align=([0-9a-f]+)&body=([0-9a-f]+))", [&](const Request& req, Response& res) {
    auto numbers = req.matches[1];
    res.set_content(numbers, "text/plain");
  });

  svr.listen("localhost", 7777);
}

