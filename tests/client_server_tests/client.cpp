#include "/home/guiaraujo/cpp-httplib/httplib.h"
#include <iostream>
#include <stdio.h>

int main(void)
{
  httplib::Client cli("localhost", 7777);
  httplib::Error err = httplib::Error::Success;

  if (auto res = cli.Get("/hia")) {
    if (res->status == 200) {
      std::cout << res->body << std::endl;
    }
  } else {
    err = res.error();
    printf("%d\n", (int)res.error());
  }

  return int(err);
}
